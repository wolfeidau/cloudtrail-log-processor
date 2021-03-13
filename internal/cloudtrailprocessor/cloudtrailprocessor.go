package cloudtrailprocessor

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/encoding/json"
	"github.com/wolfeidau/ssmcache"

	"github.com/wolfeidau/cloudtrail-log-processor/internal/flags"
	"github.com/wolfeidau/cloudtrail-log-processor/internal/rules"
)

type S3API interface {
	GetObjectWithContext(aws.Context, *s3.GetObjectInput, ...request.Option) (*s3.GetObjectOutput, error)
}

type UploaderAPI interface {
	UploadWithContext(aws.Context, *s3manager.UploadInput, ...func(*s3manager.Uploader)) (*s3manager.UploadOutput, error)
}

type Copier interface {
	Copy(ctx context.Context, bucket, key string) error
}

// Cloudtrail cloudtrail document used to store audit records
type Cloudtrail struct {
	Records []json.RawMessage
}

// Copier copies cloudtrail files between a source and destination bucket with filtering via rules
type S3Copier struct {
	s3svc     S3API
	uploadsvc UploaderAPI
	cfg       flags.S3Processor
	ssm       ssmcache.Cache
}

// NewProcessor setup a new s3 event processor
func NewCopier(cfg flags.S3Processor, awscfg *aws.Config) Copier {
	sess := session.Must(session.NewSession(awscfg))

	return &S3Copier{
		s3svc:     s3.New(sess),
		uploadsvc: s3manager.NewUploader(sess),
		cfg:       cfg,
		ssm:       ssmcache.New(awscfg),
	}
}

func (cp *S3Copier) Copy(ctx context.Context, bucket, key string) error {
	rulesCfg, err := rules.LoadFromSSMAndValidate(ctx, cp.ssm, cp.cfg.ConfigSSMParam)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("Unmarshal")
		return err
	}

	return cp.processFile(ctx, bucket, key, rulesCfg)
}

func (cp *S3Copier) processFile(ctx context.Context, bucket, key string, rulesCfg *rules.Configuration) error {
	inct, err := cp.downloadCloudtrail(ctx, bucket, key)
	if err != nil {
		return fmt.Errorf("failed to download and decode source JSON file: %w", err)
	}

	log.Ctx(ctx).Info().Int("input", len(inct.Records)).Msg("completed")

	// filter events
	outct, err := filterRecords(ctx, inct, rulesCfg)
	if err != nil {
		return fmt.Errorf("failed to filter records: %w", err)
	}

	pr, pwr := io.Pipe()

	uj := new(uploadJob)

	go uj.Start(pwr, outct)

	uploadRes, err := cp.uploadsvc.UploadWithContext(ctx, &s3manager.UploadInput{
		Body:   pr,
		Bucket: aws.String(cp.cfg.CloudtrailOutputBucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to upload file to output bucket: %w", err)
	}

	if uj.Error != nil {
		return fmt.Errorf("failed to complete upload job: %w", err)
	}

	log.Ctx(ctx).Info().
		Str("path", fmt.Sprintf("s3://%s/%s", cp.cfg.CloudtrailOutputBucketName, key)).
		Int("input", len(inct.Records)).
		Int("output", len(outct.Records)).
		Str("req", uploadRes.UploadID).
		Msg("uploaded file")

	return nil
}

func (cp *S3Copier) downloadCloudtrail(ctx context.Context, bucket, key string) (*Cloudtrail, error) {
	res, err := cp.s3svc.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = res.Body.Close()
	}()

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

func filterRecords(ctx context.Context, inct *Cloudtrail, rulesCfg *rules.Configuration) (*Cloudtrail, error) {
	outct := new(Cloudtrail)

	outct.Records = inct.Records[:0]
	rec := make(map[string]interface{})

	for _, raw := range inct.Records {
		err := json.Unmarshal(raw, &rec)
		if err != nil {
			return nil, fmt.Errorf("unmarshal record failed: %w", err)
		}

		log.Ctx(ctx).Debug().Fields(map[string]interface{}{
			"eventName":          rec["eventName"],
			"eventSource":        rec["eventSource"],
			"awsRegion":          rec["awsRegion"],
			"recipientAccountId": rec["recipientAccountId"],
		}).Msg("eval record")

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
	_ = gw.Close()
	_ = pwr.Close()
}
