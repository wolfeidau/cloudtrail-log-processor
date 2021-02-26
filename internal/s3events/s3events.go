package s3events

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/cloudtrail-log-processor/internal/flags"
)

// Processor translates s3 events into sns messages
type Processor struct {
	snssvc snsiface.SNSAPI
	cfg    flags.S3Events
}

// NewProcessor setup a new s3 event processor
func NewProcessor(cfg flags.S3Events, awscfg *aws.Config) *Processor {

	sess := session.Must(session.NewSession(awscfg))

	return &Processor{
		snssvc: sns.New(sess),
		cfg:    cfg,
	}
}

// Handler send s3 events to sns
func (ps *Processor) Handler(ctx context.Context, payload []byte) ([]byte, error) {
	log.Ctx(ctx).Info().Msg("processEvent")

	res, err := ps.snssvc.Publish(&sns.PublishInput{
		TopicArn: aws.String(ps.cfg.TopicName),
		Message:  aws.String(string(payload)),
	})
	if err != nil {
		return nil, err
	}

	log.Ctx(ctx).Info().Str("res.MessageId", aws.StringValue(res.MessageId)).Msg("sent message")

	return []byte(""), nil
}
