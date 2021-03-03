module github.com/wolfeidau/cloudtrail-log-processor

go 1.16

require (
	github.com/alecthomas/kong v0.2.15
	github.com/aws/aws-lambda-go v1.22.0
	github.com/aws/aws-sdk-go v1.37.19
	github.com/davecgh/go-spew v1.1.1
	github.com/rs/zerolog v1.20.0
	github.com/segmentio/encoding v0.2.7
	github.com/stretchr/testify v1.7.0
	github.com/wolfeidau/lambda-go-extras v1.3.0
	github.com/wolfeidau/lambda-go-extras/middleware/raw v1.3.0
	github.com/wolfeidau/lambda-go-extras/middleware/zerolog v1.3.0
	gopkg.in/yaml.v2 v2.2.8
)
