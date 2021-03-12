package flags

import "github.com/alecthomas/kong"

// S3Processor s3 processor flags
type S3Processor struct {
	Version                    kong.VersionFlag
	CloudtrailOutputBucketName string `env:"CLOUDTRAIL_OUTPUT_BUCKET_NAME"`
	ConfigSSMParam             string `env:"CONFIG_SSM_PARAM"`
	SNSPayloadType             string `env:"SNS_PAYLOAD_TYPE"`
}
