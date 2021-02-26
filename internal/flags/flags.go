package flags

import "github.com/alecthomas/kong"

// S3Events s3 events flags
type S3Events struct {
	Version    kong.VersionFlag
	TopicName  string
	BucketName string
}
