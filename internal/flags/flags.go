package flags

import "github.com/alecthomas/kong"

// S3Processor s3 processor flags
type S3Processor struct {
	Version                    kong.VersionFlag
	CloudtrailBucketName       string
	CloudtrailOutputBucketName string
}
