package cloudtrailprocessor

import (
	"bytes"
	"context"
	"fmt"
	"testing"

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

func TestProcessor_Handler(t *testing.T) {
	type setup func(ctrl *gomock.Controller, cfg flags.S3Processor) *S3Copier

	type args struct {
		bucket, key string
	}

	tests := []struct {
		name    string
		cfg     flags.S3Processor
		setup   setup
		args    args
		wantErr bool
	}{
		{
			name:  "should upload file with cloudtrail sns payload",
			cfg:   flags.S3Processor{ConfigSSMParam: "/config/whatever", SNSPayloadType: "cloudtrail"},
			setup: copierSuccess,
			args: args{
				bucket: "testbucket", key: "test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := require.New(t)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ctx := log.Logger.WithContext(context.TODO())
			fmt.Println("setup")
			cp := tt.setup(ctrl, tt.cfg)
			fmt.Println("Handler")
			err := cp.Copy(ctx, tt.args.bucket, tt.args.key)
			if (err != nil) != tt.wantErr {
				assert.Error(err)
			}
		})
	}
}

func copierSuccess(ctrl *gomock.Controller, cfg flags.S3Processor) *S3Copier {
	ssm := mocks.NewMockCache(ctrl)
	s3svc := mocks.NewMockS3API(ctrl)
	uploadsvc := mocks.NewMockUploaderAPI(ctrl)

	ssm.EXPECT().GetKey("/config/whatever", false).Return(yamlConfig, nil)

	s3svc.EXPECT().GetObjectWithContext(gomock.Any(), &s3.GetObjectInput{
		Bucket: aws.String("testbucket"), Key: aws.String("test")}, gomock.Any(),
	).Return(&s3.GetObjectOutput{Body: aws.ReadSeekCloser(bytes.NewBufferString("{}"))}, nil)

	uploadsvc.EXPECT().UploadWithContext(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&s3manager.UploadOutput{UploadID: "test"}, nil)

	return &S3Copier{
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
