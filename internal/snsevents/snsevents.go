package snsevents

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/encoding/json"
	"github.com/wolfeidau/cloudtrail-log-processor/internal/flags"
	"github.com/wolfeidau/cloudtrail-log-processor/internal/rules"
)

// Processor translates s3 events into sns messages
type Processor struct {
	s3svc s3iface.S3API
	cfg   flags.S3Processor
	rules *rules.Configuration
}

// NewProcessor setup a new s3 event processor
func NewProcessor(cfg flags.S3Processor, awscfg *aws.Config, rules *rules.Configuration) *Processor {

	sess := session.Must(session.NewSession(awscfg))

	return &Processor{
		s3svc: s3.New(sess),
		cfg:   cfg,
		rules: rules,
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

		s3Event := new(CloudtrailSNSEvent)

		err := json.Unmarshal([]byte(snsrec.SNS.Message), s3Event)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("Unmarshal")
			return nil, err
		}

		log.Ctx(ctx).Info().Strs("objects", s3Event.S3ObjectKey).Str("bucket", s3Event.S3Bucket).Msg("s3Event")

		for _, s3rec := range s3Event.S3ObjectKey {
			res, err := ps.s3svc.GetObject(&s3.GetObjectInput{
				Bucket: aws.String(s3Event.S3Bucket),
				Key:    aws.String(s3rec),
			})
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("GetObject")
				return nil, err
			}

			defer res.Body.Close()

			inct := new(Cloudtrail)
			decoder := json.NewDecoder(res.Body)
			decoder.UseNumber()
			decoder.ZeroCopy()

			err = decoder.Decode(inct)
			if err != nil {
				log.Error().Err(err).Msg("failed to decode source JSON file")
				return nil, err
			}

			log.Info().Int("input", len(inct.Records)).Msg("completed")

			// filter events
			outct, err := ps.filterRecords(inct)
			if err != nil {
				log.Error().Err(err).Msg("failed to filter records")
				return nil, err
			}

			log.Info().
				Str("path", fmt.Sprintf("s3://%s/%s", ps.cfg.CloudtrailOutputBucketName, s3rec)).
				Int("input", len(inct.Records)).
				Int("output", len(outct.Records)).
				Msg("create new file")

		}
	}

	return []byte(""), nil
}

func (ps *Processor) filterRecords(inct *Cloudtrail) (*Cloudtrail, error) {

	outct := new(Cloudtrail)

	outct.Records = inct.Records[:0]

	rec := make(map[string]interface{})

	for _, raw := range inct.Records {
		err := json.Unmarshal(raw, &rec)
		if err != nil {
			return nil, fmt.Errorf("unmarshal record failed: %w", err)
		}

		match, err := ps.rules.EvalRules(rec)
		if err != nil {
			return nil, err
		}
		// because we are using the rules to filter records a match means drop
		if match {
			continue // next record
		}

		outct.Records = append(outct.Records, raw)
	}

	return outct, nil
}

// Cloudtrail cloudtrail document used to store audit records
type Cloudtrail struct {
	Records []json.RawMessage
}

// CloudtrailSNSEvent event provided in the default SNS topic when a new file is written to the s3 bucket
type CloudtrailSNSEvent struct {
	S3Bucket    string   `json:"s3Bucket,omitempty"`
	S3ObjectKey []string `json:"s3ObjectKey,omitempty"`
}
