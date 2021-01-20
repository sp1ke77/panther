package api

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/panther-labs/panther/pkg/awsutils"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	awspoller "github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws"
	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/datacatalog"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/stringset"
)

var (
	putIntegrationInternalError = &genericapi.InternalError{Message: "Failed to add source. Please try again later"}
)

// PutIntegration adds a set of new integrations in a batch.
func (api *API) PutIntegration(input *models.PutIntegrationInput) (newIntegration *models.SourceIntegration, err error) {
	if err := api.validateIntegration(input); err != nil {
		zap.L().Error("failed to put integration", zap.Error(err))
		return nil, err
	}

	// Filter out existing integrations
	if err := api.integrationAlreadyExists(input); err != nil {
		zap.L().Error("failed to put integration", zap.Error(err))
		return nil, err
	}

	// Generate the new integration from the input
	newIntegration = api.generateNewIntegration(input)

	// First creating table - this action is idempotent. In case we succeed here and
	// fail at a later stage, in case of retry this will succeed again.
	if err = api.createTables(newIntegration); err != nil {
		zap.L().Error("failed to create Glue tables", zap.Error(err))
		return nil, putIntegrationInternalError
	}

	// Write to DynamoDB
	item := integrationToItem(newIntegration)
	if err = api.DdbClient.PutItem(item); err != nil {
		zap.L().Error("failed to store source integration in DDB", zap.Error(err))
		return nil, putIntegrationInternalError
	}

	// Try to setupExternalResources. Do this after saving the integration to the db.
	// This way, if setting up any external resources fails, we can clean up partially created
	// resources when the user deletes the integration from the UI.
	if err := api.setupExternalResources(newIntegration); err != nil {
		zap.L().Error("failed to setup external resources", zap.Error(err))
		return nil, putIntegrationInternalError
	}

	if input.IntegrationType == models.IntegrationTypeAWSScan {
		err = api.FullScan(&models.FullScanInput{Integrations: []*models.SourceIntegrationMetadata{&newIntegration.SourceIntegrationMetadata}})
		if err != nil {
			zap.L().Error("failed to trigger scanning of resources", zap.Error(err))
			return nil, putIntegrationInternalError
		}
	}

	return newIntegration, nil
}

func (api *API) setupExternalResources(integration *models.SourceIntegration) error {
	switch integration.IntegrationType {
	case models.IntegrationTypeAWS3:
		if err := api.AllowExternalSnsTopicSubscription(integration.AWSAccountID); err != nil {
			return errors.Wrap(err, "failed to add permissions to log processor queue")
		}
		if integration.ManagedBucketNotifications {
			// TODO(giorgosp): If managed notifs fail, don't fail the request? FE will prompt user
			// to create them automatically.
			// TODO(giorgosp):-if someone deletes an integration and there is no other integration
			//  using that bucket, we should delete that SNS topic/notification. ?

			// TODO(giorgosp): if ManagedBucketNotifications, healthcheck should check for this topic.

			sess := session.Must(session.NewSession(&aws.Config{
				CredentialsChainVerboseErrors: aws.Bool(true),
			}))
			stsSess, err := session.NewSession(&aws.Config{
				CredentialsChainVerboseErrors: aws.Bool(true),
				Region:                        aws.String(endpoints.UsEast1RegionID), // Bucket region
				MaxRetries:                    aws.Int(3),
				Credentials:                   stscreds.NewCredentials(sess, integration.LogProcessingRole),
			})
			if err != nil {
				return errors.Wrap(err, "failed to setup bucket notifications")
			}

			err = configureNotifications(stsSess, integration)
			if err != nil {
				return errors.Wrap(err, "failed to setup bucket notifications")
			}
		}
	case models.IntegrationTypeSqs:
		if err := api.AllowInputDataBucketSubscription(); err != nil {
			return errors.Wrap(err, "failed to enable subscription for input bucket")
		}
		if err := api.CreateSourceSqsQueue(integration.IntegrationID,
			integration.SqsConfig.AllowedPrincipalArns, integration.SqsConfig.AllowedSourceArns); err != nil {
			return errors.Wrap(err, "failed to create input SQS queue")
		}
		if err := api.AddSourceAsLambdaTrigger(integration.IntegrationID); err != nil {
			return errors.Wrap(err, "failed to configure queue as lambda source")
		}
	}
	return nil
}

func configureNotifications(sess *session.Session, integration *models.SourceIntegration) error {
	snsClient := sns.New(sess)
	s3Client := s3.New(sess)

	//TODO(giorgosp) If Get/Put notifications fail, don't delete the previously created resources.
	// User can manually set them up.
	// If Topic/TopicPolicy/Subscription fails, delete the previous resources so that user can
	// install the panther-log-processing-notifications.yml stack manually.

	// Create the topic.
	topic, err := snsClient.CreateTopic(&sns.CreateTopicInput{
		Name: aws.String("panther-notifications-topic"),
	})
	if err != nil {
		return errors.Wrap(err, "failed to create topic")
	}

	// Set the topic policy, as defined in deployments/auxiliary/cloudformation/panther-log-processing-notifications.yml.
	topicPolicy := awsutils.PolicyDocument{
		Version: "2012-10-17",
		Statement: []awsutils.StatementEntry{
			{
				Sid: "AllowS3EventNotifications",
				Effect:   "Allow",
				Action:   "sns:Publish",
				Resource: *topic.TopicArn,
				Principal: awsutils.Principal{
					Service: "s3.amazonaws.com",
				},
			}, {
				Sid: "AllowCloudTrailNotification",
				Effect:   "Allow",
				Action:   "sns:Publish",
				Resource: *topic.TopicArn,
				Principal: awsutils.Principal{
					Service: "cloudtrail.amazonaws.com",
				},
			},
		},
	}
	topicPolicyJSON, err := jsoniter.MarshalToString(topicPolicy)
	if err != nil {
		return errors.Wrap(err, "failed to marshal topic policy")
	}
	//TODO(giorgosp): Add retries for eventual consistency issues from CreateTopic()
	_, err = snsClient.SetTopicAttributes(&sns.SetTopicAttributesInput{
		TopicArn:       topic.TopicArn,
		AttributeName:  aws.String("Policy"),
		AttributeValue: aws.String(topicPolicyJSON),
	})
	if err != nil {
		return errors.Wrap(err, "failed to set topic policy")
	}

	// Subscribe topic to Panther input data queue
	sub := sns.SubscribeInput{
		// TODO(giorgosp): Replace partition, region and account id with Panther's installation values.
		Endpoint: aws.String("arn:<panther-partition>:sqs:<panther-region>:<panther-acccount-id>:panther-input-data-notifications-queue"),
		Protocol: aws.String("sqs"),
		TopicArn: topic.TopicArn,
	}
	_, err = snsClient.Subscribe(&sub)
	if err != nil {
		return errors.Wrapf(err, "failed to subscribe topic to %s", sub.Endpoint)
	}

	// Setup bucket notifications
	getInput := s3.GetBucketNotificationConfigurationRequest{
		Bucket:              &integration.S3Bucket,
		ExpectedBucketOwner: &integration.AWSAccountID,
	}
	config, err := s3Client.GetBucketNotificationConfiguration(&getInput)
	if err != nil {
		return errors.Wrap(err, "failed to get bucket notifications")
	}

	for _, prefix := range integration.S3PrefixLogTypes.S3Prefixes() {
		tc := s3.TopicConfiguration{
			Id: aws.String("panther-managed-" + uuid.New().String()),
			Events: []*string{aws.String("s3:ObjectCreated:*")},
			Filter: &s3.NotificationConfigurationFilter{
				Key: &s3.KeyFilter{
					FilterRules: []*s3.FilterRule{{
						Name:  aws.String("prefix"),
						Value: aws.String(prefix),
					}},
				},
			},
			TopicArn: topic.TopicArn,
		}
		config.TopicConfigurations = append(config.TopicConfigurations, &tc)
	}

	putInput := s3.PutBucketNotificationConfigurationInput{
		Bucket:                    &integration.S3Bucket,
		ExpectedBucketOwner:       &integration.AWSAccountID,
		NotificationConfiguration: config,
	}
	_, err = s3Client.PutBucketNotificationConfiguration(&putInput)
	if err != nil {
		return errors.Wrap(err, "failed to put bucket notifications")
	}

	return nil
}

func (api *API) validateIntegration(input *models.PutIntegrationInput) error {
	// Prefixes in the same S3 source should should be unique (although we allow overlapping for now)
	// todo(giorgosp): Don't allow overlapping prefixes - only for new sources.
	if input.IntegrationType == models.IntegrationTypeAWS3 {
		prefixes := input.S3PrefixLogTypes.S3Prefixes()
		if len(prefixes) != len(stringset.Dedup(prefixes)) {
			return &genericapi.InvalidInputError{
				Message: "Cannot have duplicate prefixes in an s3 source.",
			}
		}
	}

	// Validate the new integration
	reason, passing, err := api.EvaluateIntegrationFunc(&models.CheckIntegrationInput{
		AWSAccountID:      input.AWSAccountID,
		IntegrationType:   input.IntegrationType,
		IntegrationLabel:  input.IntegrationLabel,
		EnableCWESetup:    input.CWEEnabled,
		EnableRemediation: input.RemediationEnabled,
		S3Bucket:          input.S3Bucket,
		S3PrefixLogTypes:  input.S3PrefixLogTypes,
		KmsKey:            input.KmsKey,
		SqsConfig:         input.SqsConfig,
	})
	if err != nil {
		return putIntegrationInternalError
	}
	if !passing {
		zap.L().Warn("PutIntegration: resource has a misconfiguration",
			zap.Error(err),
			zap.String("reason", reason),
			zap.Any("input", input))
		return &genericapi.InvalidInputError{
			Message: fmt.Sprintf("Source %s did not pass configuration check. %s",
				input.IntegrationLabel, reason),
		}
	}
	return nil
}

func (api API) integrationAlreadyExists(input *models.PutIntegrationInput) error {
	// avoid inserting if already done
	existingIntegrations, err := api.ListIntegrations(&models.ListIntegrationsInput{})
	if err != nil {
		zap.L().Error("failed to fetch integrations", zap.Error(errors.WithStack(err)))
		return putIntegrationInternalError
	}

	for _, existingIntegration := range existingIntegrations {
		if existingIntegration.IntegrationType == input.IntegrationType {
			switch existingIntegration.IntegrationType {
			case models.IntegrationTypeAWSScan:
				if existingIntegration.AWSAccountID == input.AWSAccountID {
					// We can only have one cloudsec integration for each account
					return &genericapi.InvalidInputError{
						Message: fmt.Sprintf("Source account %s already onboarded", input.AWSAccountID),
					}
				}
				return nil
			case models.IntegrationTypeAWS3:
				if existingIntegration.AWSAccountID == input.AWSAccountID &&
					existingIntegration.IntegrationLabel == input.IntegrationLabel {
					// Log sources for same account need to have different labels
					return &genericapi.InvalidInputError{
						Message: fmt.Sprintf("Log source for account %s with label %s already onboarded",
							input.AWSAccountID,
							input.IntegrationLabel),
					}
				}

				// A bucket/prefix combination should be unique among s3 sources.
				if existingIntegration.S3Bucket == input.S3Bucket {
					for _, existingPrefix := range existingIntegration.S3PrefixLogTypes.S3Prefixes() {
						for _, prefix := range input.S3PrefixLogTypes.S3Prefixes() {
							if strings.TrimSpace(existingPrefix) == strings.TrimSpace(prefix) {
								return &genericapi.InvalidInputError{
									Message: "An S3 source with the same S3 bucket and prefix already exists.",
								}
							}
						}
					}
				}
			case models.IntegrationTypeSqs:
				if existingIntegration.IntegrationLabel == input.IntegrationLabel {
					// Sqs sources need to have different labels
					return &genericapi.InvalidInputError{
						Message: fmt.Sprintf("Integration with label %s already exists", input.IntegrationLabel),
					}
				}
			}
		}
	}

	return nil
}

// FullScan schedules scans for each Resource type for each integration.
//
// Each Resource type is sent within its own SQS message.
func (api *API) FullScan(input *models.FullScanInput) error {
	var sqsEntries []*sqs.SendMessageBatchRequestEntry

	// For each integration, add a ScanMsg to the queue per service
	for _, integration := range input.Integrations {
		for resourceType := range awspoller.ServicePollers {
			scanMsg := &pollermodels.ScanMsg{
				Entries: []*pollermodels.ScanEntry{
					{
						AWSAccountID:            &integration.AWSAccountID,
						IntegrationID:           &integration.IntegrationID,
						ResourceType:            aws.String(resourceType),
						Enabled:                 integration.Enabled,
						RegionIgnoreList:        integration.RegionIgnoreList,
						ResourceTypeIgnoreList:  integration.ResourceTypeIgnoreList,
						ResourceRegexIgnoreList: integration.ResourceRegexIgnoreList,
					},
				},
			}

			messageBodyBytes, err := jsoniter.MarshalToString(scanMsg)
			if err != nil {
				return &genericapi.InternalError{Message: err.Error()}
			}

			sqsEntries = append(sqsEntries, &sqs.SendMessageBatchRequestEntry{
				// Generates an ID of: IntegrationID-AWSResourceType
				Id: aws.String(
					integration.IntegrationID + "-" + strings.Replace(resourceType, ".", "", -1),
				),
				MessageBody: aws.String(messageBodyBytes),
			})
		}
	}

	zap.L().Info(
		"scheduling new scans",
		zap.String("queueUrl", api.Config.SnapshotPollersQueueURL),
		zap.Int("count", len(sqsEntries)),
	)

	// Batch send all the messages to SQS
	_, err := sqsbatch.SendMessageBatch(api.SqsClient, 5*time.Second, &sqs.SendMessageBatchInput{
		Entries:  sqsEntries,
		QueueUrl: &api.Config.SnapshotPollersQueueURL,
	})
	return err
}

func (api *API) generateNewIntegration(input *models.PutIntegrationInput) *models.SourceIntegration {
	metadata := models.SourceIntegrationMetadata{
		CreatedAtTime:    time.Now(),
		CreatedBy:        input.UserID,
		IntegrationID:    uuid.New().String(),
		IntegrationLabel: input.IntegrationLabel,
		IntegrationType:  input.IntegrationType,
	}

	switch input.IntegrationType {
	case models.IntegrationTypeAWSScan:
		metadata.AWSAccountID = input.AWSAccountID
		metadata.CWEEnabled = input.CWEEnabled
		metadata.LogProcessingRole = api.Config.InputDataRoleArn
		metadata.RemediationEnabled = input.RemediationEnabled
		metadata.ScanIntervalMins = input.ScanIntervalMins
		metadata.StackName = getStackName(input.IntegrationType, input.IntegrationLabel)
		metadata.S3Bucket = api.Config.InputDataBucketName
	case models.IntegrationTypeAWS3:
		metadata.AWSAccountID = input.AWSAccountID
		metadata.S3Bucket = input.S3Bucket
		metadata.S3PrefixLogTypes = input.S3PrefixLogTypes
		metadata.KmsKey = input.KmsKey
		metadata.S3PrefixLogTypes = input.S3PrefixLogTypes
		metadata.StackName = getStackName(input.IntegrationType, input.IntegrationLabel)
		metadata.LogProcessingRole = generateLogProcessingRoleArn(input.AWSAccountID, input.IntegrationLabel)
		metadata.Enabled = input.Enabled
		metadata.RegionIgnoreList = input.RegionIgnoreList
		metadata.ResourceTypeIgnoreList = input.ResourceTypeIgnoreList
		metadata.ResourceRegexIgnoreList = input.ResourceRegexIgnoreList
	case models.IntegrationTypeSqs:
		metadata.SqsConfig = &models.SqsConfig{
			S3Bucket:             api.Config.InputDataBucketName,
			LogProcessingRole:    api.Config.InputDataRoleArn,
			AllowedPrincipalArns: input.SqsConfig.AllowedPrincipalArns,
			AllowedSourceArns:    input.SqsConfig.AllowedSourceArns,
			LogTypes:             input.SqsConfig.LogTypes,
			QueueURL:             api.SourceSqsQueueURL(metadata.IntegrationID),
		}
	}
	return &models.SourceIntegration{
		SourceIntegrationMetadata: metadata,
	}
}

func (api *API) createTables(integration *models.SourceIntegration) error {
	client := datacatalog.Client{
		SQSAPI:   api.SqsClient,
		QueueURL: api.Config.DataCatalogUpdaterQueueURL,
	}
	logTypes := integration.RequiredLogTypes()
	err := client.SendCreateTablesForLogTypes(context.TODO(), logTypes...)
	if err != nil {
		return errors.Wrap(err, "failed to create Glue tables")
	}
	return nil
}
