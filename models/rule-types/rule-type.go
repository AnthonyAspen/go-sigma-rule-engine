package ruletypes

type RuleType string

const (
	DefaultRule RuleType = ""
	EventCount  RuleType = "event_type"
	ValueCount  RuleType = "value_count"
	Temporal    RuleType = "temporal"
)
