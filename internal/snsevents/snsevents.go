package snsevents

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/encoding/json"
	"github.com/wolfeidau/cloudtrail-log-processor/internal/flags"
	"github.com/wolfeidau/cloudtrail-log-processor/internal/rules"
	"github.com/wolfeidau/ssmcache"
)

// Processor translates s3 events into sns messages
type Processor struct {
	s3svc     s3iface.S3API
	uploadsvc s3manageriface.UploaderAPI
	cfg       flags.S3Processor
	ssm       ssmcache.Cache
}

// NewProcessor setup a new s3 event processor
func NewProcessor(cfg flags.S3Processor, awscfg *aws.Config) *Processor {

	sess := session.Must(session.NewSession(awscfg))

	return &Processor{
		s3svc:     s3.New(sess),
		uploadsvc: s3manager.NewUploader(sess),
		cfg:       cfg,
		ssm:       ssmcache.New(awscfg),
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

	rulesCfg, err := rules.LoadFromSSMAndValidate(ctx, ps.ssm, ps.cfg.ConfigSSMParam)
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
			err := ps.processFile(ctx, s3Event.S3Bucket, s3rec, rulesCfg)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("failed to process file")
				return nil, err
			}
		}
	}

	return []byte(""), nil
}

func (ps *Processor) processFile(ctx context.Context, bucket, key string, rulesCfg *rules.Configuration) error {
	inct, err := ps.downloadCloudtrail(ctx, bucket, key)
	if err != nil {
		return fmt.Errorf("failed to download and decode source JSON file: %w", err)
	}

	log.Ctx(ctx).Info().Int("input", len(inct.Records)).Msg("completed")

	// filter events
	outct, err := ps.filterRecords(inct, rulesCfg)
	if err != nil {
		return fmt.Errorf("failed to filter records: %w", err)
	}

	pr, pwr := io.Pipe()

	uj := new(uploadJob)

	go uj.Start(pwr, outct)

	uploadParams := &s3manager.UploadInput{
		Body:   pr,
		Bucket: aws.String(ps.cfg.CloudtrailOutputBucketName),
		Key:    aws.String(key),
	}

	uploadRes, err := ps.uploadsvc.Upload(uploadParams)
	if err != nil {
		return fmt.Errorf("failed to upload file to output bucket: %w", err)
	}

	if uj.Error != nil {
		return fmt.Errorf("failed to complete upload job: %w", err)
	}

	log.Ctx(ctx).Info().
		Str("path", fmt.Sprintf("s3://%s/%s", ps.cfg.CloudtrailOutputBucketName, key)).
		Int("input", len(inct.Records)).
		Int("output", len(outct.Records)).
		Str("req", uploadRes.UploadID).
		Msg("uploaded file")

	return nil
}

func (ps *Processor) downloadCloudtrail(ctx context.Context, bucket, key string) (*Cloudtrail, error) {
	res, err := ps.s3svc.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	inct := new(Cloudtrail)
	decoder := json.NewDecoder(res.Body)
	decoder.UseNumber()
	decoder.ZeroCopy()

	err = decoder.Decode(inct)
	if err != nil {
		return nil, err
	}

	return inct, nil
}

func (ps *Processor) filterRecords(inct *Cloudtrail, rulesCfg *rules.Configuration) (*Cloudtrail, error) {

	outct := new(Cloudtrail)

	outct.Records = inct.Records[:0]
	rec := make(map[string]interface{})

	for _, raw := range inct.Records {
		err := json.Unmarshal(raw, &rec)
		if err != nil {
			return nil, fmt.Errorf("unmarshal record failed: %w", err)
		}

		match, err := rulesCfg.EvalRules(rec)
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

// helps track encoding / streaming errors for a go routine
type uploadJob struct {
	Error error
}

// streams json in the background when the writer is consumed
func (uj *uploadJob) Start(pwr io.WriteCloser, out interface{}) {
	gw := gzip.NewWriter(pwr)

	encoder := json.NewEncoder(gw)
	encoder.SetSortMapKeys(false)
	uj.Error = encoder.Encode(out)
	gw.Close()
	pwr.Close()
}
