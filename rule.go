package sigma

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

// Rule defines raw rule conforming to sigma rule specification
// https://github.com/Neo23x0/sigma/wiki/Specification
// only meant to be used for parsing yaml that matches Sigma rule definition
type SimpleRule struct {
	Name   string `yaml:"name" json:"name"`
	Author string `yaml:"author" json:"author"`
	// Date           *time.Time `yaml:"date" json:"date"`
	// Modified       *time.Time `yaml:"modified" json:"modified"`
	Description    string   `yaml:"description" json:"description"`
	Falsepositives []string `yaml:"falsepositives" json:"falsepositives"`
	Fields         []string `yaml:"fields" json:"fields"`
	ID             string   `yaml:"id" json:"id"`
	Level          string   `yaml:"level" json:"level"`
	Title          string   `yaml:"title" json:"title"`
	Status         string   `yaml:"status" json:"status"`
	References     []string `yaml:"references" json:"references"`

	Logsource Logsource `yaml:"logsource" json:"logsource"`
	Detection Detection `yaml:"detection" json:"detection"`
	Tags      Tags      `yaml:"tags" json:"tags"`
}

type Rule interface {
	NewTree() (*Tree, error)
}

// Logsource represents the logsource field in sigma rule
// It defines relevant event streams and is used for pre-filtering
type Logsource struct {
	Product    string `yaml:"product" json:"product"`
	Category   string `yaml:"category" json:"category"`
	Service    string `yaml:"service" json:"service"`
	Definition string `yaml:"definition" json:"definition"`
}

// Detection represents the detection field in sigma rule
// contains condition expression and identifier fields for building AST
type Detection map[string]interface{}

func (d Detection) ExtractCondition() map[string]interface{} {
	tx := make(map[string]interface{})
	for k, v := range d {
		if k != "condition" {
			tx[k] = v
		}
	}
	return tx
}

// Tags contains a metadata list for tying positive matches together with other threat intel sources
// For example, for attaching MITRE ATT&CK tactics or techniques to the event
type Tags []string

// RulesFromFiles reads a list of sigma rule paths and parses them to rule objects
func RulesFromFiles(files []string) ([]Rule, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("missing rule file list")
	}

	tempRules := map[string]map[string][]byte{}
	rules := make([]Rule, 0, len(files))

	for _, path := range files {
		var tempRule map[string]interface{}

		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Println(err.Error())
			return nil, err
		}

		if len(data) == 0 {
			fmt.Printf("skipping empty file: %s\n", path)
			continue
		}

		if bytes.Contains(data, []byte("---")) {
			return nil, errors.New("multipart files are not supported")
		}

		if err := yaml.Unmarshal(data, &tempRule); err != nil {
			return nil, &ErrParseYaml{Err: err, Path: path}
		}

		if name, ok := tempRule["name"].(string); ok {
			// no need to check for error. because if action is empty, it'll be regular rule by default.
			action, _ := tempRule["action"].(string)
			tempRules[name] = map[string][]byte{
				action: data,
			}
		}

	}

	// iterate over the map that contains map [action] fileBytes
	// and determine rule struct by action that it has
	for _, actions := range tempRules {
		for action, rule := range actions {
			if action != "" {
				var corrRule Correlation
				if err := yaml.Unmarshal(rule, &corrRule); err != nil {
					return nil, &ErrParseYaml{Err: err}
				}

				// find all rules or correlations mentioned in correlation
				for _, v := range corrRule.RulesString {
					val, ok := tempRules[v]
					if !ok {
						return nil, fmt.Errorf("not found rule mentioned in correlation:%s", val)
					}

					// here should be only one rule, if not - something went wrong
					if len(val) != 1 {
						return nil, errors.New("something went wrong with number elements in a map")
					}

					for _, rule := range rules {

						tree, err := rule.NewTree()
						// FIXME this will calculate tree 2 times,
						// fix the logic
						if err != nil {
							return nil, err
						}
						corrRule.Matchers = append(corrRule.Matchers, tree)
					}
				}
				rules = append(rules, corrRule)
			}
			if action == "" {
				var simpleRule SimpleRule
				if err := yaml.Unmarshal(rule, &simpleRule); err != nil {
					return nil, &ErrParseYaml{Err: err}
				}

				rules = append(rules, simpleRule)
			}
		}
	}

	return rules, nil
}

// Result is an object returned on positive sigma match
type Result struct {
	Tags `json:"tags"`

	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Results should be returned when single event matches multiple rules
type Results []Result

// NewRuleFileList finds all yaml files from defined root directories
// Subtree is scanned recursively
// No file validation, other than suffix matching
func NewRuleFileList(dirs []string) ([]string, error) {
	if len(dirs) == 0 {
		return nil, errors.New("rule directories undefined")
	}
	out := make([]string, 0)
	for _, dir := range dirs {
		if err := filepath.Walk(dir, func(
			path string,
			info os.FileInfo,
			err error,
		) error {
			if !info.IsDir() && strings.HasSuffix(path, "yml") {
				out = append(out, path)
			}
			return err
		}); err != nil {
			return out, err
		}
	}
	return out, nil
}

// func splitMultipartYAML(resources []byte) ([][]byte, error) {
// 	dec := yaml.NewDecoder(bytes.NewReader(resources))
// 	var res [][]byte
// 	for {
// 		var value interface{}
// 		err := dec.Decode(&value)
// 		if err == io.EOF {
// 			break
// 		}
// 		if err != nil {
// 			return nil, err
// 		}
// 		valueBytes, err := yaml.Marshal(value)
// 		if err != nil {
// 			return nil, err
// 		}
// 		res = append(res, valueBytes)
// 	}
// 	return res, nil
// }

// var allByteSlices, err = SplitYAML([]byte(sampleYAML))
