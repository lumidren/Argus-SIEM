package cloudtrail

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

const iamUser = `"userIdentity":{"type":"IAMUser","principalId":"AIDAEXAMPLE","arn":"arn:aws:iam::111122223333:user/alice","accountId":"111122223333","accessKeyId":"AKIAEXAMPLE","userName":"alice"}`

func TestConsoleLogin(t *testing.T) {
	raw := `{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDAEXAMPLE","arn":"arn:aws:iam::111122223333:user/alice","accountId":"111122223333","userName":"alice"},"eventTime":"2024-06-01T09:15:32Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.20","userAgent":"Mozilla/5.0","requestParameters":null,"responseElements":{"ConsoleLogin":"Success"},"additionalEventData":{"LoginTo":"https://console.aws.amazon.com","MobileVersion":"No","MFAUsed":"Yes"},"eventID":"e1","readOnly":false,"eventType":"AwsConsoleSignIn","managementEvent":true,"recipientAccountId":"111122223333","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_128_GCM_SHA256","clientProvidedHostHeader":"signin.aws.amazon.com"}}`
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.000Z", "event.dataset": "aws.cloudtrail", "event.id": "e1", "event.action": "ConsoleLogin",
		"event.provider": "signin.amazonaws.com", "event.category": []string{"authentication"}, "event.type": []string{"start"},
		"event.outcome": "success", "cloud.provider": "aws", "cloud.region": "us-east-1", "cloud.account.id": "111122223333",
		"source.ip": "198.51.100.20", "user.name": "alice", "user.id": "AIDAEXAMPLE", "user_agent.original": "Mozilla/5.0",
		"aws.cloudtrail.console_login.additional_eventdata.mfa_used": true, "aws.cloudtrail.user_identity.type": "IAMUser",
		"aws.cloudtrail.tls_details.tls_version": "TLSv1.3", "aws.cloudtrail.event_type": "AwsConsoleSignIn", "aws.cloudtrail.management_event": true,
		"aws.cloudtrail.flattened.response_elements.ConsoleLogin": "Success",
	})
	raw = `{"eventVersion":"1.08",` + iamUser + `,"eventTime":"2024-06-01T09:16:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.20","responseElements":{"ConsoleLogin":"Failure"},"errorMessage":"Failed authentication","eventID":"e2"}`
	e = parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{"event.outcome": "failure", "aws.cloudtrail.error_message": "Failed authentication"})
}

func TestIAMAndConfig(t *testing.T) {
	e := parsertest.ParseOne(t, New(), `{"eventVersion":"1.08",`+iamUser+`,"eventTime":"2024-06-01T09:20:00Z","eventSource":"iam.amazonaws.com","eventName":"CreateUser","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.20","requestParameters":{"userName":"bob","tags":[{"key":"team","value":"data"}]},"responseElements":{"user":{"userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"}},"eventID":"e3"}`)
	parsertest.Expect(t, e, map[string]any{
		"event.category": []string{"iam"}, "event.type": []string{"creation"}, "aws.cloudtrail.flattened.request_parameters.userName": "bob",
		"aws.cloudtrail.flattened.response_elements.user.arn": "arn:aws:iam::111122223333:user/bob",
		"aws.cloudtrail.request_parameters":                   `{"tags":[{"key":"team","value":"data"}],"userName":"bob"}`,
	})
	e = parsertest.ParseOne(t, New(), `{"eventVersion":"1.08",`+iamUser+`,"eventTime":"2024-06-01T09:21:00Z","eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy","awsRegion":"eu-west-1","sourceIPAddress":"198.51.100.20","requestParameters":{"bucketName":"reports-bucket"},"eventID":"e4"}`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"configuration"}, "event.type": []string{"change"}, "aws.cloudtrail.flattened.request_parameters.bucketName": "reports-bucket", "cloud.service.name": "s3"})
	e = parsertest.ParseOne(t, New(), `{"eventVersion":"1.08",`+iamUser+`,"eventTime":"2024-06-01T09:22:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","readOnly":true,"sourceIPAddress":"198.51.100.20","requestParameters":{"bucketName":"reports-bucket","key":"q2.csv"},"resources":[{"type":"AWS::S3::Object","ARN":"arn:aws:s3:::reports-bucket/q2.csv"}],"eventID":"e5","eventCategory":"Data"}`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"file"}, "event.type": []string{"access"}, "aws.cloudtrail.read_only": true})
	e = parsertest.ParseOne(t, New(), `{"eventVersion":"1.08",`+iamUser+`,"eventTime":"2024-06-01T09:23:00Z","eventSource":"ec2.amazonaws.com","eventName":"RunInstances","sourceIPAddress":"198.51.100.20","errorCode":"Client.UnauthorizedOperation","errorMessage":"You are not authorized to perform this operation.","eventID":"e6"}`)
	parsertest.Expect(t, e, map[string]any{"event.outcome": "failure", "event.type": []string{"creation"}, "aws.cloudtrail.error_code": "Client.UnauthorizedOperation"})
}

func TestIdentitiesAndEnvelopes(t *testing.T) {
	assumed := `{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLE:deploy-session","arn":"arn:aws:sts::111122223333:assumed-role/DeployRole/deploy-session","accountId":"111122223333","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"AROAEXAMPLE","arn":"arn:aws:iam::111122223333:role/DeployRole","accountId":"111122223333","userName":"DeployRole"},"attributes":{"creationDate":"2024-06-01T09:00:00Z","mfaAuthenticated":"false"}}},"eventTime":"2024-06-01T09:24:00Z","eventSource":"lambda.amazonaws.com","eventName":"UpdateFunctionCode20150331v2","sourceIPAddress":"198.51.100.21","eventID":"e7"}`
	svc := `{"eventVersion":"1.08","userIdentity":{"type":"AWSService","invokedBy":"cloudtrail.amazonaws.com"},"eventTime":"2024-06-01T09:25:00Z","eventSource":"s3.amazonaws.com","eventName":"GetBucketAcl","sourceIPAddress":"cloudtrail.amazonaws.com","eventID":"e8"}`
	evs, err := New().Parse(parsertest.Input(`{"Records":[`+assumed+`,`+svc+`]}`, nil))
	if err != nil || len(evs) != 2 {
		t.Fatalf("records envelope: %d %v", len(evs), err)
	}
	parsertest.Expect(t, evs[0], map[string]any{
		"user.name": "deploy-session", "aws.cloudtrail.user_identity.session_context.session_issuer.user_name": "DeployRole",
		"aws.cloudtrail.user_identity.session_context.mfa_authenticated": false, "event.type": []string{"change"},
	})
	parsertest.Expect(t, evs[1], map[string]any{"source.address": "cloudtrail.amazonaws.com", "user.name": "cloudtrail.amazonaws.com", "aws.cloudtrail.user_identity.invoked_by": "cloudtrail.amazonaws.com"})
	parsertest.ExpectAbsent(t, evs[1], "source.ip")

	eb := `{"version":"0","detail-type":"AWS API Call via CloudTrail","source":"aws.iam","detail":{"eventVersion":"1.08","userIdentity":{"type":"Root","principalId":"111122223333","arn":"arn:aws:iam::111122223333:root"},"eventTime":"2024-06-01T09:26:00Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","sourceIPAddress":"198.51.100.22","eventID":"e9"}}`
	if !New().Detect([]byte(eb), nil) {
		t.Fatal("eventbridge not detected")
	}
	e := parsertest.ParseOne(t, New(), eb)
	parsertest.Expect(t, e, map[string]any{"user.name": "Root", "event.category": []string{"iam"}, "event.type": []string{"creation"}})
}

func TestDetect(t *testing.T) {
	p := New()
	for _, s := range []string{`{"a":1}`, `{"eventType":"user.session.start","published":"x"}`, `{"records":[{"operationName":"x"}]}`, `x`} {
		if p.Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := p.Parse(parsertest.Input(`{"Records":[]}`, nil)); err == nil {
		t.Fatal("empty envelope should error")
	}
	_ = sortedKeys(map[string]any{"b": 1, "a": 2})
}
