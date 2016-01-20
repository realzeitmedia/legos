package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	indexTmpl  = flag.String("index", "logstash-20060102", "index name")
	hosts      = flag.String("hosts", "localhost:9200", "ES hosts (,)")
	lineRegexp = flag.String("regexp", glog, "regexp with capture groups")
	verbose    = flag.Bool("verbose", true, "verbose")
)

func main() {
	flag.Parse()

	lineReg := regexp.MustCompile(*lineRegexp) // TODO: nicer error
	if *verbose {
		fmt.Printf("using regexp: %q\n", lineRegexp)
	}

	es := bubbles.New(strings.Split(*hosts, ","),
		bubbles.OptFlush(1*time.Second),
	)

	defer func() {
		fmt.Printf("shutting down...\n")
		time.Sleep(2 * time.Second) // more than the ES flush time
	}()

	var (
		r   = bufio.NewReader(os.Stdin)
		l   string
		err error
	)
	subexps := lineReg.SubexpNames()
	for ; err == nil; l, err = r.ReadString('\n') {
		if l == "" {
			continue
		}
		if *verbose {
			fmt.Printf("line: %q\n", l)
		}

		t := time.Now()
		fields := map[string]string{
			"@timestamp": t.Format(time.RFC3339), // almost: 2016-01-19T09:33:45+01:00
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
			fmt.Printf("Index: %s\n", index)
			fmt.Printf("Fields:\n")
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
	if err != io.EOF {
		fmt.Printf("error: %s", err)
	}
}
