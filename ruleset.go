package sigma

import (
	"fmt"
	"os"
	"sync"
)

// Config is used as argument to creating a new ruleset
type Config struct {
	// root directory for recursive rule search
	// rules must be readable files with "yml" suffix
	Directory []string
}

func (c Config) validate() error {
	if c.Directory == nil || len(c.Directory) == 0 {
		return fmt.Errorf("missing root directory for sigma rules")
	}
	for _, dir := range c.Directory {
		info, err := os.Stat(dir)
		if os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
	}
	return nil
}

// Ruleset is a collection of rules
type Ruleset struct {
	mu *sync.RWMutex

	Rules []*Tree
	root  []string
}

// NewRuleset instanciates a Ruleset object
func NewRuleset(c Config) (*Ruleset, error) {
	var err error

	if err := c.validate(); err != nil {
		return nil, err
	}
	files, err := NewRuleFileList(c.Directory)
	if err != nil {
		return nil, err
	}
	rules, err := RulesFromFiles(files)
	if err != nil {
		return nil, err
	}

	set := make([]*Tree, 0)

	for _, raw := range rules {
		tree, err := NewTree(raw)
		if err != nil {
			return nil, err
		}
		set = append(set, tree)
	}

	return &Ruleset{
		mu:    &sync.RWMutex{},
		Rules: set,
	}, err
}

func (r *Ruleset) EvalAll(e Event) (Results, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	results := make(Results, 0)
	for _, rule := range r.Rules {
		if res, match := rule.Eval(e); match {
			results = append(results, *res)
		}
	}
	if len(results) > 0 {
		return results, true
	}
	return nil, false
}
