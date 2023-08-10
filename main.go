package main

import (
	"flag"
	"fmt"
	"os"
	"pass2lastp/pkg/password"
)

func main() {
	var lastpCSV, safariCSV, out string

	flag.StringVar(&lastpCSV, "lastp", "", "Path to LastPass CSV export file")
	flag.StringVar(&safariCSV, "safari", "", "Path to Safari passwords CSV export file")
	flag.StringVar(&out, "o", "-", "Path to store differences, - is stdout")
	flag.Parse()

	var outfp *os.File
	if out == "-" {
		outfp = os.Stdout
	} else {
		fp, err := os.OpenFile(out, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		outfp = fp
		defer outfp.Close()
	}
	conflicts, err := password.DoDiff(safariCSV, lastpCSV)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Found %d conflicts\n", len(conflicts))
	for _, p := range conflicts {
		_, _ = outfp.WriteString(p.String())
	}
}
