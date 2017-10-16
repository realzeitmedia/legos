package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/realzeitmedia/bubbles"
)

const (
	// Go glog logs
	glog = `^\S+ \S+ \S+\s+\d+ (?P<file>.+):\d+\] (?P<msg>(?P<msgcore>.*?:)?.*)`

	// Nginx access logs
	// 1.2.3.4 - - [18/Feb/2016:10:05:22 +0000] "GET /client/assets/some.css HTTP/1.1" 200 1090 "https://somereferer" "Mozilla/5.0 (Linux; Android 5.1.1; D6603 Build/23.4.A.1.264; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/47.0.2526.100 Mobile Safari/537.36 (Mobile; afma-sdk-a-v8489000.7327000.1)"
	nginx = `^(?P<remote>[^ ]*) (?P<host>[^ ]*) (?P<user>[^ ]*) \[[^\]]*\] "(?P<method>\S+)(?: +(?P<path>[^\"]*) +\S*)?" (?P<code>[^ ]*) (?P<size>[^ ]*)(?: "(?P<referer>[^\"]*)" "(?P<agent>[^\"]*)")?$`

	// Nginx error logs
	// 2016/02/18 10:06:44 [crit] 13679#0: *3683 SSL_do_handshake() failed (SSL: error:140A1175:SSL routines:SSL_BYTES_TO_CIPHER_LIST:inappropriate fallback) while SSL handshaking, client: 1.2.3.4, server: 0.0.0.0:443
	nginxerror = `^.* \[(?P<level>\w+)\] (?P<msg>.*)$`

	// Rails multiline. We don't deal with these nicely.
	// I, [2016-02-18T11:27:36.879342 #14224]  INFO -- : Completed 200 OK in 141ms (Views: 95.1ms | ActiveRecord: 9.7ms)
	// I, [2016-02-18T11:27:36.882539 #14200]  INFO -- : Started PATCH "/some/url" for 1.2.3.4 at 2016-02-18 11:27:36 +0000
	// F, [2016-02-18T06:52:19.155825 #30782] FATAL -- :
	// PG::ConnectionBad (could not connect to server: Connection refused
	//     Is the server running on host "localhost" (127.0.0.1) and accepting
	//     TCP/IP connections on port 5432?
	// ):
	//   vendor/bundle/ruby/2.1.0/gems/activerecord-4.0.2/lib/active_record/connection_adapters/postgresql_adapter.rb:831:in `initialize'
	rails = `^[DIEF], \[.*\]\s+(?P<level>\w+)\s+-- : (?P<msg>.*)$`

	MaxFieldLength = 30000 // ES doesn't like more than 32K
)

var (
	namedRegexpes = [][3]string{
		{"glog", glog, "go glog formats"},
		{"example", `(?P<msg>.{0,10})`, "example"},
		{"nginx", nginx, "nginx access logs"},
		{"nginxerror", nginxerror, "nginx error logs"},
		{"rails", rails, "basic rails output. Ignores multiline errors"},
	}
	indexTmpl   = flag.String("index", "logstash-20060102", "index name")
	hosts       = flag.String("hosts", "localhost:9200", "ES hosts (,)")
	lineRegexp  = flag.String("regexp", glog, "freeform regexp with capture groups")
	namedRegexp = flag.String("named", "", "predefined regexp, see -list. overrules -regexp")
	verbose     = flag.Bool("verbose", false, "verbose")
	copy        = flag.Bool("copy", false, "copy all lines to STDOUT")
	list        = flag.Bool("list", false, "list all named regexpes and exit")
)

// limit the length of a string to
func limit(s string) string {
	if len(s) > MaxFieldLength {
		s = s[:MaxFieldLength] + "..."
	}
	return s
}

func main() {
	flag.Parse()
	if len(flag.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "too many arguments\n")
		os.Exit(1)
	}

	if *list {
		fmt.Printf("regexps available for -named:\n")
		for _, e := range namedRegexpes {
			fmt.Printf("  -named=%s\n   desc: %s\n   regexp: /%s/\n", e[0], e[2], e[1])
		}
		return
	}

	if *copy && *verbose {
		fmt.Fprintf(os.Stderr, "can't enable both -verbose and -copy\n")
		os.Exit(1)
	}

	var lreg = *lineRegexp
	if *namedRegexp != "" {
		for _, e := range namedRegexpes {
			if e[0] == *namedRegexp {
				lreg = e[1]
				break
			}
		}

	}
	if lreg == "" {
		fmt.Fprintf(os.Stderr, "no regexp give. Use either -named or -regexp\n")
		os.Exit(2)
	}

	lineReg, err := regexp.Compile(lreg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -regexp: %s\n", err)
		os.Exit(2)
	}
	if *verbose {
		fmt.Printf("using regexp: %q\n", lreg)
	}

	es := bubbles.New(strings.Split(*hosts, ","),
		bubbles.OptFlush(1*time.Second),
	)

	defer func() {
		if *verbose {
			fmt.Printf("shutting down...\n")
		}
		time.Sleep(2 * time.Second) // more than the ES flush time
	}()

	var (
		r       = bufio.NewScanner(bufio.NewReader(os.Stdin))
		subexps = lineReg.SubexpNames()
	)
	for r.Scan() {
		l := r.Text()
		if *verbose {
			fmt.Printf("line: %q\n", l)
		}
		if *copy {
			fmt.Println(l)
		}

		t := time.Now()
		fields := map[string]string{
			"@timestamp": t.Format(time.RFC3339Nano),
			"message":    limit(l),
		}
		if m := lineReg.FindStringSubmatch(l); m != nil {
			for i, v := range m {
				if i == 0 {
					continue
				}
				fields[subexps[i]] = limit(v)
			}
		}
		index := t.Format(*indexTmpl)
		if *verbose {
			fmt.Printf("index: %s\n", index)
			fmt.Printf("fields:\n")
			for n, v := range fields {
				fmt.Printf("  %s: %q\n", n, v)
			}
		}

		doc, err := json.Marshal(fields)
		if err != nil {
			panic(fmt.Sprintf("encode error: %s\n", err))
		}

		es.Enqueue(bubbles.Action{
			Type: bubbles.Index,
			MetaData: bubbles.MetaData{
				Index: index,
				Type:  "legos",
				// no ID
			},
			Document: string(doc),
		})
	}
}
