package main

import (
	"github.com/alecthomas/kong"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	lmw "github.com/wolfeidau/lambda-go-extras/middleware"
	"github.com/wolfeidau/lambda-go-extras/middleware/raw"
	zlog "github.com/wolfeidau/lambda-go-extras/middleware/zerolog"

	"github.com/wolfeidau/cloudtrail-log-processor/internal/flags"
	"github.com/wolfeidau/cloudtrail-log-processor/internal/snsevents"
)

var (
	version = "unknown"

	cfg = new(flags.S3Processor)
)

func main() {
	kong.Parse(cfg,
		kong.Vars{"version": version}, // bind a var for version
	)

	flds := lmw.FieldMap{"version": version}

	ps := snsevents.NewProcessor(*cfg, &aws.Config{})

	ch := lmw.New(
		raw.New(raw.Fields(flds)),   // raw event logger primarily used during development
		zlog.New(zlog.Fields(flds)), // inject zerolog into the context
	).ThenFunc(ps.Handler)

	lambda.StartHandler(ch)
}
