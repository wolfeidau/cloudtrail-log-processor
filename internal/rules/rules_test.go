package rules

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/wolfeidau/cloudtrail-log-processor/mocks"
)

var yamlConfig = `
---
rules:
  - name: check_kms
    matches:
    - field_name: eventName
      regex: ".*crypt"
    - field_name: eventSource
      regex: "kms.*"

`

func TestRules(t *testing.T) {
	assert := require.New(t)

	ctr, err := Load(yamlConfig)
	assert.NoError(err)

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

func TestLoadFromSSMAndValidate(t *testing.T) {
	assert := require.New(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ssm := mocks.NewMockCache(ctrl)

	ssm.EXPECT().GetKey("/config/whatever", false).Return(yamlConfig, nil)

	rulesCfg, err := LoadFromSSMAndValidate(context.TODO(), ssm, "/config/whatever")
	assert.NoError(err)

	assert.Equal(&Configuration{Rules: []*Rule{{
		Name: "check_kms",
		Matches: []*Match{
			{
				FieldName: "eventName",
				Regex:     ".*crypt",
			},
			{
				FieldName: "eventSource",
				Regex:     "kms.*",
			},
		},
	}}}, rulesCfg)
}
