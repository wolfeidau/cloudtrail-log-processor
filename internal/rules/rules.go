package rules

import (
	"context"
	"fmt"
	"regexp"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/ssmcache"
	"gopkg.in/yaml.v2"
)

// Configuration configuration containing our rules which are used to filter events
type Configuration struct {
	Rules []*Rule `yaml:"rules" validate:"required,dive"`
}

// Validate validate the configuration rules
func (cr *Configuration) Validate() error {
	validate := validator.New()

	err := validate.RegisterValidation("is-regex", ValidateIsRegex)
	if err != nil {
		return err
	}

	return validate.Struct(cr)
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

// Load load the configuration from the provided string
func Load(rawCfg string) (*Configuration, error) {
	ctr := new(Configuration)

	err := yaml.Unmarshal([]byte(rawCfg), ctr)
	if err != nil {
		return nil, err
	}

	return ctr, nil
}

// LoadFromSSMAndValidate load the configuration from ssmcache and validate it
func LoadFromSSMAndValidate(ctx context.Context, ssm ssmcache.Cache, path string) (*Configuration, error) {
	log.Ctx(ctx).Info().Str("path", path).Msg("loading config from ssmcache")

	rawCfg, err := ssm.GetKey(path, false) // config is not encrypted
	if err != nil {
		return nil, fmt.Errorf("read config from ssm failed: %w", err)
	}

	rulesCfg, err := Load(rawCfg)
	if err != nil {
		return nil, fmt.Errorf("load rules configuration failed: %w", err)
	}

	err = rulesCfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("rules validation failed: %w", err)
	}

	return rulesCfg, nil
}

// Rule rule with a name, and one or more matches
type Rule struct {
	Name    string   `yaml:"name" validate:"required"`
	Matches []*Match `yaml:"matches" validate:"required,dive"`
}

// Match match containing the field to be checked and the REGEX used to match
type Match struct {
	FieldName string `yaml:"field_name" validate:"required,oneof=eventName eventSource awsRegion recipientAccountId"`
	Regex     string `yaml:"regex" validate:"is-regex"`
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

				mt, err := regexp.MatchString(mtch.Regex, vs)
				if err != nil {
					return false, err
				}

				b = b && mt
			}
		}
	}

	return b, nil
}

// ValidateIsRegex implements validator.Func
func ValidateIsRegex(fl validator.FieldLevel) bool {
	_, err := regexp.Compile(fl.Field().String())
	return err == nil
}
