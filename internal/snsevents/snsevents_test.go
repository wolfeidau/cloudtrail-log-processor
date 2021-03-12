package snsevents

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/encoding/json"
	"github.com/stretchr/testify/require"

	"github.com/wolfeidau/cloudtrail-log-processor/internal/flags"
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

var (
	goodSNSCloudtrailEvent = &events.SNSEvent{Records: []events.SNSEventRecord{
		{SNS: events.SNSEntity{
			MessageID: "abc123abc123",
			Message: mustJSONString(
				&CloudtrailSNSEvent{S3Bucket: "testbucket", S3ObjectKeys: []string{"test"}},
			)},
		},
	}}

	goodSNSS3Event = &events.SNSEvent{Records: []events.SNSEventRecord{{SNS: events.SNSEntity{
		MessageID: "abc123abc123",
		Message: mustJSONString(
			&events.S3Event{Records: []events.S3EventRecord{{S3: events.S3Entity{
				Bucket: events.S3Bucket{Name: "testbucket"}, Object: events.S3Object{Key: "test"}},
			}}},
		)}},
	}}
)

func TestProcessor_Handler(t *testing.T) {
	type setup func(ctrl *gomock.Controller, cfg flags.S3Processor) *Processor

	type args struct {
		payload []byte
	}

	tests := []struct {
		name    string
		cfg     flags.S3Processor
		setup   setup
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:  "should upload file with cloudtrail sns payload",
			cfg:   flags.S3Processor{ConfigSSMParam: "/config/whatever", SNSPayloadType: "cloudtrail"},
			setup: processorSuccess,
			args: args{
				payload: mustJSON(goodSNSCloudtrailEvent),
			},
			want: []byte{},
		},
		{
			name:  "should upload file with s3 sns payload",
			cfg:   flags.S3Processor{ConfigSSMParam: "/config/whatever", SNSPayloadType: "s3"},
			setup: processorSuccess,
			args: args{
				payload: mustJSON(goodSNSS3Event),
			},
			want: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := require.New(t)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ctx := log.Logger.WithContext(context.TODO())
			fmt.Println("setup")
			ps := tt.setup(ctrl, tt.cfg)
			fmt.Println("Handler")
			got, err := ps.Handler(ctx, tt.args.payload)
			if (err != nil) != tt.wantErr {
				assert.Error(err)
			}
			assert.Equal(tt.want, got)
		})
	}
}

func processorSuccess(ctrl *gomock.Controller, cfg flags.S3Processor) *Processor {
	ssm := mocks.NewMockCache(ctrl)
	s3svc := mocks.NewMockS3API(ctrl)
	uploadsvc := mocks.NewMockUploaderAPI(ctrl)

	ssm.EXPECT().GetKey("/config/whatever", false).Return(yamlConfig, nil)

	s3svc.EXPECT().GetObjectWithContext(gomock.Any(), &s3.GetObjectInput{
		Bucket: aws.String("testbucket"), Key: aws.String("test")}, gomock.Any(),
	).Return(&s3.GetObjectOutput{Body: aws.ReadSeekCloser(bytes.NewBufferString("{}"))}, nil)

	uploadsvc.EXPECT().UploadWithContext(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&s3manager.UploadOutput{UploadID: "test"}, nil)

	return &Processor{
		cfg:       cfg,
		ssm:       ssm,
		s3svc:     s3svc,
		uploadsvc: uploadsvc,
	}
}

func mustJSON(in interface{}) []byte {
	data, err := json.Marshal(in)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))

	return data
}

func mustJSONString(in interface{}) string {
	return string(mustJSON(in))
}
