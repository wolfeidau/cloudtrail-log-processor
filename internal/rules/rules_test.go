package rules

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

var yamlConfig = `
---
rules:
  - name: check_kms
    matches:
    - field_name: eventName
      matches: ".*crypt"
    - field_name: eventSource
      matches: "kms.*"

`

func TestRules(t *testing.T) {
	assert := require.New(t)

	ctr := new(Configuration)

	err := yaml.Unmarshal([]byte(yamlConfig), ctr)
	assert.NoError(err)

	spew.Dump(ctr)

	err = ctr.Validate()
	assert.NoError(err)

	match, err := ctr.Rules[0].Eval(map[string]interface{}{
		"eventName":   "Encrypt",
		"eventSource": "kms.amazonaws.com",
	})
	assert.NoError(err)
	assert.True(match)

	match, err = ctr.Rules[0].Eval(map[string]interface{}{
		"eventName":   "Encrypt",
		"eventSource": "logs.amazonaws.com",
	})
	assert.NoError(err)
	assert.False(match)
}
