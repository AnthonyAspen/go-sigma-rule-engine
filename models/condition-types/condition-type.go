package conditiontypes

type ConditionType string

const (
	// gt: the count must be greater than the given value
	GreaterThan ConditionType = "gt"
	// gte: the count must be greater than or equal the given value
	GreaterThanEqual ConditionType = "gte"
	// lt: the count must be lesser than the given value
	LesserThan ConditionType = "ls"
	// lte: the count must be lesser than or equal the given value
	LesserThanEqual ConditionType = "lse"
	// range: the count must be in the given range specified as value in the format min..max. The ranges include the min and max values.
	Range ConditionType = "range"
)
