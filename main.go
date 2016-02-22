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
	glog = `^\S+ \S+ \S+\s+\d+ (?P<file>.+):\d+\] (?P<msg>(?P<msgcore>.*?:)?.*)`
)

var (
	namedRegexpes = [][2]string{
		{"glog", glog},
		{"debug", `(?P<msg>)`},
	}
)

var (
	indexTmpl   = flag.String("index", "logstash-20060102", "index name")
	hosts       = flag.String("hosts", "localhost:9200", "ES hosts (,)")
	lineRegexp  = flag.String("regexp", glog, "freeform regexp with capture groups")
	namedRegexp = flag.String("named", "", "predefined regexp, see -list. overrules -regexp")
	verbose     = flag.Bool("verbose", false, "verbose")
	copy        = flag.Bool("copy", false, "copy all lines to STDOUT")
	list        = flag.Bool("list", false, "list all named regexpes and exit")
)

func main() {
	flag.Parse()
	if len(flag.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "too many arguments\n")
		os.Exit(1)
	}

	if *list {
		fmt.Printf("regexps available for -named:\n")
		for _, e := range namedRegexpes {
			fmt.Printf("  -named=%s -> `%s`\n", e[0], e[1])
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
			"message":    l,
		}
		if m := lineReg.FindStringSubmatch(l); m != nil {
			for i, v := range m {
				if i == 0 {
					continue
				}
				fields[subexps[i]] = v
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

		es.Enqueue() <- bubbles.Action{
			Type: bubbles.Index,
			MetaData: bubbles.MetaData{
				Index: index,
				Type:  "legos",
				// no ID
			},
			Document: string(doc),
		}
	}
}
