package sigma

import (
	"time"

	"github.com/AnthonyAspen/go-sigma-rule-engine/models/actions"
	conditionTypes "github.com/AnthonyAspen/go-sigma-rule-engine/models/condition-types"
	ruleTypes "github.com/AnthonyAspen/go-sigma-rule-engine/models/rule-types"
)

type Correlation struct {
	Name string `yaml:"name" json:"name"`
	// Action will be correlation for correlations, and empty for rules.
	Action actions.Action `yaml:"action" json:"action"`
	// event_count, value_count, temporal
	Type      ruleTypes.RuleType                           `yaml:"type" json:"type"`
	Condition map[conditionTypes.ConditionType]interface{} `yaml:"condition" json:"condition"`

	// RulesString exists for a first step of getting rules of a correlation
	RulesString []string `yaml:"rules" json:"-"`

	Matchers []Matcher `yaml:"-" json:"rules"`

	GroupBy []string `yaml:"group-by" json:"group_by"`

	// Timespan defines a time period in which the correlation should be applied.
	// The following format must be used: number + letter (in lowercase)
	//     Xs seconds
	//     Xm minutes
	//     Xh hours
	//     Xd days
	Timespan *time.Duration `yaml:"timespan" json:"timespan"`
}

// NewTree parses rule handle into an abstract syntax tree
func (c Correlation) NewTree() (*Tree, error) {
	t := &Tree{
		Root: c,
		Rule: &c,
	}
	return t, nil
}

func (c *Correlation) Matcher(e Event) (bool, bool) {
	for _, r := range c.Matchers {
		match, applicable := r.Match(e)
		if !applicable || !match {
			return false, false
		}

	}

	return true, true
}

func (c Correlation) Match(e Event) (bool, bool) {
	for _, r := range c.Matchers {
		match, applicable := r.Match(e)
		if !applicable || !match {
			return false, false
		}

	}

	return true, true
}
