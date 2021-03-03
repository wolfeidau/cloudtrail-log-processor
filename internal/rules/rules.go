package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var fields = map[string]string{
	"eventName":   "",
	"eventSource": "",
	"awsRegion":   "",
	"accountId":   "",
}

type ValidationErrors []FieldError

func (ve ValidationErrors) Error() string {

	buff := bytes.NewBufferString("")

	for i := 0; i < len(ve); i++ {
		buff.WriteString(fmt.Sprintf("rule index: %d field: %s error: %s", ve[i].Index, ve[i].Field, ve[i].Description))
		buff.WriteString("\n")
	}

	return strings.TrimSpace(buff.String())
}

type FieldError struct {
	Index       int
	Field       string
	Description string
}

// Configuration configuration containing our rules which are used to filter events
type Configuration struct {
	Rules []Rule `yaml:"rules,omitempty"`
}

// Validate validate the configuration rules
func (cr *Configuration) Validate() error {
	var valErrors ValidationErrors
	for n, rule := range cr.Rules {

		if rule.Name == "" {
			valErrors = append(valErrors, FieldError{Index: n, Field: "", Description: "missing name"})

		}

		for _, mtch := range rule.Matches {
			_, ok := fields[mtch.FieldName]
			if !ok {
				valErrors = append(valErrors, FieldError{Index: n, Field: mtch.FieldName, Description: "invalid field"})
			}

			_, err := regexp.Compile(mtch.Matches)
			if err != nil {
				valErrors = append(valErrors, FieldError{Index: n, Field: mtch.FieldName, Description: fmt.Sprintf("invalid regex: %v", err)})
			}
		}
	}

	if len(valErrors) > 0 {
		return valErrors
	}

	return nil
}

// EvalRules iterate over all rules and return a match if one evaluates to true
func (cr *Configuration) EvalRules(evt map[string]interface{}) (bool, error) {
	for _, rule := range cr.Rules {
		match, err := rule.Eval(evt)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}

	}

	return false, nil
}

// Rule rule with a name, and one or more matches
type Rule struct {
	Name    string  `json:"name,omitempty"`
	Matches []Match `json:"matches,omitempty"`
}

// Match match containing the field to be checked and the REGEX used to match
type Match struct {
	FieldName string `yaml:"field_name,omitempty"`
	Matches   string `yaml:"matches,omitempty"`
}

// Eval evaluate the match for a given event, this will run each field check in the rule
// if ALL evaluate to true
func (mc *Rule) Eval(evt map[string]interface{}) (bool, error) {

	b := true

	for k, v := range evt {
		for _, mtch := range mc.Matches {
			if mtch.FieldName == k {
				// if the value is not a string skip the matching
				vs, ok := v.(string)
				if !ok {
					continue
				}

				mt, err := regexp.MatchString(mtch.Matches, vs)
				if err != nil {
					return false, err
				}

				b = b && mt
			}
		}
	}

	return b, nil
}
