package main

import (
	"log"

	"github.com/AnthonyAspen/go-sigma-rule-engine"
)

type counts struct {
	ok, fail, unsupported int
}

func main() {
	files := []string{
		"rule.yml",
		"corr_rule.yml",
	}

	rules, err := sigma.RulesFromFiles(files)
	if err != nil {
		switch err.(type) {
		case sigma.ErrBulkParseYaml:
			log.Println(err)
		default:
			log.Fatal(err)
		}
	}
	log.Printf("Got %d rules from yaml\n", len(rules))
	log.Println("Parsing rules into AST")
	c := &counts{}
	for _, raw := range rules {
		_, err := raw.NewTree()
		if err != nil {
			switch err.(type) {
			case sigma.ErrUnsupportedToken:
				c.unsupported++
				log.Printf("%s: \n", err)
			default:
				c.fail++
				log.Printf("%s\n", err)
			}
		} else {
			c.ok++
		}
	}

	log.Printf("OK: %d; FAIL: %d; UNSUPPORTED: %d\n", c.ok, c.fail, c.unsupported)
}
