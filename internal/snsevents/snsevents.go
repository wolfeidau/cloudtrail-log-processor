package snsevents

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/encoding/json"

	"github.com/wolfeidau/cloudtrail-log-processor/internal/cloudtrailprocessor"
	"github.com/wolfeidau/cloudtrail-log-processor/internal/flags"
)

// Processor translates s3 events into sns messages
type Processor struct {
	cfg    flags.S3Processor
	copier cloudtrailprocessor.Copier
}

// NewProcessor setup a new s3 event processor
func NewProcessor(cfg flags.S3Processor, awscfg *aws.Config) *Processor {
	return &Processor{
		cfg:    cfg,
		copier: cloudtrailprocessor.NewCopier(cfg, awscfg),
	}
}

// Handler send s3 events to sns
func (ps *Processor) Handler(ctx context.Context, payload []byte) ([]byte, error) {
	log.Ctx(ctx).Info().Msg("processEvent")

	snsEvent := new(events.SNSEvent)

	err := json.Unmarshal(payload, snsEvent)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("Unmarshal")
		return nil, err
	}

	for _, snsrec := range snsEvent.Records {
		log.Ctx(ctx).Info().Str("id", snsrec.SNS.MessageID).Msg("Records")

		switch ps.cfg.SNSPayloadType {
		case "cloudtrail":
			s3Event := new(CloudtrailSNSEvent)

			err := json.Unmarshal([]byte(snsrec.SNS.Message), s3Event)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("Unmarshal")
				return nil, err
			}

			for _, s3ObjectKey := range s3Event.S3ObjectKeys {
				err := ps.copier.Copy(ctx, s3Event.S3Bucket, s3ObjectKey)
				if err != nil {
					log.Ctx(ctx).Error().Err(err).Msg("failed to process file")
					return nil, err
				}
			}
		case "s3":
			s3Event := new(events.S3Event)
			err := json.Unmarshal([]byte(snsrec.SNS.Message), s3Event)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("Unmarshal")
				return nil, err
			}

			for _, s3EventRecord := range s3Event.Records {
				err := ps.copier.Copy(ctx, s3EventRecord.S3.Bucket.Name, s3EventRecord.S3.Object.Key)
				if err != nil {
					log.Ctx(ctx).Error().Err(err).Msg("failed to process file")
					return nil, err
				}
			}

		default:
			return nil, fmt.Errorf("failed to process SNSPayloadType: %s", ps.cfg.SNSPayloadType)
		}
	}

	return []byte(""), nil
}

// CloudtrailSNSEvent event provided in the default SNS topic when a new file is written to the s3 bucket
type CloudtrailSNSEvent struct {
	S3Bucket     string   `json:"s3Bucket,omitempty"`
	S3ObjectKeys []string `json:"s3ObjectKey,omitempty"`
}
