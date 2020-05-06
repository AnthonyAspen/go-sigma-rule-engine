package sigma

import (
	"fmt"

	"github.com/ryanuber/go-glob"
)

// Tree represents the full AST for a sigma rule
type Tree struct {
	Root Branch
}

// Match implements Matcher
func (t Tree) Match(e Event) bool {
	return t.Root.Match(e)
}

// NewTree parses rule handle into an abstract syntax tree
func NewTree(r *RuleHandle) (*Tree, error) {
	if r == nil {
		return nil, fmt.Errorf("Missing rule handle")
	}
	if r.Detection == nil {
		return nil, ErrMissingDetection{}
	}
	expr, ok := r.Detection["condition"].(string)
	if !ok {
		return nil, ErrMissingCondition{}
	}

	p := &parser{
		lex:       lex(expr),
		condition: expr,
		sigma:     r.Detection,
	}
	if err := p.run(); err != nil {
		return nil, err
	}
	t := &Tree{Root: p.result}
	return t, nil
}

// newBranch builds a binary tree from token list
// sequence and group validation should be done before invoking newBranch
func newBranch(d Detection, t []Item, depth int) (Branch, error) {
	rx := genItems(t)

	and := make(NodeSimpleAnd, 0)
	or := make(NodeSimpleOr, 0)
	var negated bool
	var wildcard Token

	for item := range rx {
		switch item.T {
		case TokIdentifier:
			val, ok := d[item.Val]
			if !ok {
				return nil, ErrMissingConditionItem{Key: item.Val}
			}
			b, err := newRuleFromIdent(val, checkIdentType(item.Val, val))
			if err != nil {
				return nil, err
			}
			and = append(and, newNodeNotIfNegated(b, negated))
			negated = false
		case TokKeywordAnd:
			// no need to do anything special here
		case TokKeywordOr:
			// fill OR gate with collected AND nodes
			// reduce will strip AND logic if only one token has been collected
			or = append(or, and.Reduce())
			// reset existing AND collector
			and = make(NodeSimpleAnd, 0)
		case TokKeywordNot:
			negated = true
		case TokSepLpar:
			// recursively create new branch and append to existing list
			// then skip to next token after grouping
			b, err := newBranch(d, extractGroup(rx), depth+1)
			if err != nil {
				return nil, err
			}
			and = append(and, newNodeNotIfNegated(b, negated))
			negated = false
		case TokIdentifierAll:
			switch wildcard {
			case TokStAll:
				rules, err := extractAllToRules(d)
				if err != nil {
					return nil, err
				}
				and = append(and, newNodeNotIfNegated(NodeSimpleAnd(rules), negated))
				negated = false
			case TokStOne:
				rules, err := extractAllToRules(d)
				if err != nil {
					return nil, err
				}
				and = append(and, newNodeNotIfNegated(NodeSimpleOr(rules), negated))
				negated = false
			default:
				return nil, fmt.Errorf("Invalid wildcard ident, missing 1 of/ all of prefix")
			}
		case TokIdentifierWithWildcard:
			switch wildcard {
			case TokStAll:
				// build logical conjunction
				rules, err := extractAndBuildBranches(d, item.Val)
				if err != nil {
					return nil, err
				}
				and = append(and, newNodeNotIfNegated(NodeSimpleAnd(rules), negated))
				negated = false
			case TokStOne:
				// build logical disjunction
				rules, err := extractAndBuildBranches(d, item.Val)
				if err != nil {
					return nil, err
				}
				and = append(and, newNodeNotIfNegated(NodeSimpleOr(rules), negated))
				negated = false
			default:
				// invalid case, did not see 1of/allof statement before wildcard ident
				return nil, fmt.Errorf("Invalid wildcard ident, missing 1 of/ all of prefix")
			}
			wildcard = TokBegin
		case TokStAll:
			wildcard = TokStAll
		case TokStOne:
			wildcard = TokStOne
		case TokSepRpar:
			return nil, fmt.Errorf("parser error, should not see %s",
				TokSepRpar)
		default:
			return nil, ErrUnsupportedToken{
				Msg: fmt.Sprintf("%s | %s", item.T, item.T.Literal()),
			}
		}
	}
	or = append(or, newNodeNotIfNegated(and.Reduce(), negated))

	return or.Reduce(), nil
}

func extractGroup(rx <-chan Item) []Item {
	// fn is called when newBranch hits TokSepLpar
	// it will be consumed, so balance is already 1
	balance := 1
	group := make([]Item, 0)
	for item := range rx {
		if balance > 0 {
			group = append(group, item)
		}
		switch item.T {
		case TokSepLpar:
			balance++
		case TokSepRpar:
			balance--
			if balance == 0 {
				return group[:len(group)-1]
			}
		default:
		}
	}
	return group
}

func extractAndBuildBranches(d Detection, g string) ([]Branch, error) {
	vals, err := extractWildcardIdents(d, g)
	if err != nil {
		return nil, err
	}
	rules := make(NodeSimpleAnd, len(vals))
	for i, v := range vals {
		b, err := newRuleFromIdent(v, identSelection)
		if err != nil {
			return nil, err
		}
		rules[i] = b
	}
	return rules, nil
}

func extractWildcardIdents(d Detection, g string) ([]interface{}, error) {
	rules := make([]interface{}, 0)
	for k, v := range d {
		if glob.Glob(g, k) {
			rules = append(rules, v)
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("ident %s did not match any values", g)
	}
	return rules, nil
}

func extractAllToRules(d Detection) ([]Branch, error) {
	rules := make([]Branch, 0)
	for k, v := range d.Extract() {
		b, err := newRuleFromIdent(v, checkIdentType(k, v))
		if err != nil {
			return nil, err
		}
		rules = append(rules, b)
	}
	return rules, nil
}
