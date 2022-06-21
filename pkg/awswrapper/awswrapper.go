package awswrapper

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/eks/eksiface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/pkg/errors"
)

const (
	trustTemplate = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::%s:oidc-provider/%s"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "%s:sub": "system:serviceaccount:%s:%s"
        }
      }
    }
  ]
}`
)

type AWSWrapper interface {
	EnsurePolicy(policyName string, policyDocument []byte) error
	EnsureRole(roleName string, policyName, trustPolicy string) error
	TrustPolicyFromCluster(clusterName, namespace, serviceAccount string) (string, error)
	TrustPolicyFromOIDCIssuer(issuer, namespace, serviceAccount string) string
}

type awsWrapper struct {
	accountID string
	iam       iamiface.IAMAPI
	eks       eksiface.EKSAPI
	sts       stsiface.STSAPI
}

type policyStatement struct {
	Effect   string
	Action   []string
	Resource string
}

type policyDocument struct {
	Version   string
	Statement []policyStatement
}

func isNoSuchEntityError(err error) bool {
	if err == nil {
		return false
	}
	if awsErr, ok := err.(awserr.Error); ok {
		if awsErr.Code() == iam.ErrCodeNoSuchEntityException {
			return true
		}
	}
	return false
}

func cleanPolicy(buf []byte) (string, error) {
	var doc policyDocument
	if err := json.Unmarshal(buf, &doc); err != nil {
		return "", err
	}
	policy, err := json.Marshal(&doc)
	if err != nil {
		return "", err
	}
	return string(policy), nil
}

func New(region, endpoint string) (AWSWrapper, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:   aws.String(region),
		Endpoint: aws.String(endpoint),
	})
	if err != nil {
		return nil, err
	}
	a := &awsWrapper{
		iam: iam.New(sess),
		eks: eks.New(sess),
		sts: sts.New(sess),
	}
	if err := a.ensureAccountID(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *awsWrapper) arn(resourceType, resourceName string) *string {
	return aws.String(fmt.Sprintf("arn:aws:iam::%s:%s/%s", a.accountID, resourceType, resourceName))
}

func (a *awsWrapper) ensureAccountID() error {
	if a.accountID != "" {
		return nil
	}
	result, err := a.sts.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return err
	}
	a.accountID = aws.StringValue(result.Account)
	return nil
}

func (a *awsWrapper) TrustPolicyFromOIDCIssuer(issuer, namespace, serviceAccount string) string {
	return fmt.Sprintf(trustTemplate, a.accountID, issuer, issuer, namespace, serviceAccount)
}

func (a *awsWrapper) TrustPolicyFromCluster(clusterName, namespace, serviceAccount string) (string, error) {
	describeClusterResult, err := a.eks.DescribeCluster(&eks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		return "", errors.Wrapf(err, "describe cluster")
	}
	if describeClusterResult.Cluster == nil ||
		describeClusterResult.Cluster.Identity == nil ||
		describeClusterResult.Cluster.Identity.Oidc == nil {
		return "", errors.Wrapf(err, "describe cluster missing OIDC information")
	}
	issuer := aws.StringValue(describeClusterResult.Cluster.Identity.Oidc.Issuer)
	return a.TrustPolicyFromOIDCIssuer(issuer, namespace, serviceAccount), nil
}

func (a *awsWrapper) EnsureRole(roleName, policyName, trustPolicy string) error {
	log.Printf("Ensuring role %s", roleName)
	getResult, err := a.iam.GetRole(&iam.GetRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil && !isNoSuchEntityError(err) {
		return errors.Wrapf(err, "get role %s", roleName)
	}
	if isNoSuchEntityError(err) {
		_, err := a.iam.CreateRole(&iam.CreateRoleInput{
			AssumeRolePolicyDocument: aws.String(trustPolicy),
			RoleName:                 aws.String(roleName),
		})
		if err != nil {
			return errors.Wrapf(err, "create role %s", roleName)
		}
		log.Printf("Created role %s", roleName)
	} else if aws.StringValue(getResult.Role.AssumeRolePolicyDocument) != trustPolicy {
		if _, err := a.iam.UpdateAssumeRolePolicy(&iam.UpdateAssumeRolePolicyInput{
			RoleName:       aws.String(roleName),
			PolicyDocument: aws.String(trustPolicy),
		}); err != nil {
			return errors.Wrapf(err, "update role %s trust policy", roleName)
		}
		log.Printf("Updated role %s trust policy", roleName)
	}
	listAttachedPoliciesResult, err := a.iam.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return errors.Wrapf(err, "list role %s attached policies", roleName)
	}
	found := false
	policyARN := a.arn("policy", policyName)
	for _, policy := range listAttachedPoliciesResult.AttachedPolicies {
		getPolicyResult, err := a.iam.GetPolicy(&iam.GetPolicyInput{
			PolicyArn: policy.PolicyArn,
		})
		if err != nil {
			return errors.Wrapf(err, "get policy %s for role %s", aws.StringValue(policy.PolicyArn), roleName)
		}
		if aws.StringValue(getPolicyResult.Policy.Arn) == aws.StringValue(policyARN) {
			found = true
			break
		}
		log.Printf("Found attached policy %s for role %s", policyName, roleName)
	}
	if !found {
		_, err := a.iam.AttachRolePolicy(&iam.AttachRolePolicyInput{
			PolicyArn: policyARN,
			RoleName:  aws.String(roleName),
		})
		if err != nil {
			return errors.Wrapf(err, "attach policy %s to role %s", policyName, roleName)
		}
		log.Printf("Attached policy %s to role %s", policyName, roleName)
	}
	return nil
}

func (a *awsWrapper) EnsurePolicy(policyName string, policyDocument []byte) error {
	log.Printf("Ensuring policy %s", policyName)
	document, err := cleanPolicy(policyDocument)
	if err != nil {
		return errors.Wrapf(err, "(de)serializing policy document")
	}
	policyARN := a.arn("policy", policyName)
	getResult, err := a.iam.GetPolicy(&iam.GetPolicyInput{
		PolicyArn: policyARN,
	})
	if err != nil && !isNoSuchEntityError(err) {
		return err
	}
	if isNoSuchEntityError(err) {
		_, err := a.iam.CreatePolicy(&iam.CreatePolicyInput{
			PolicyDocument: aws.String(document),
			PolicyName:     aws.String(policyName),
		})
		if err != nil {
			return err
		}
		log.Printf("Created policy %s", policyName)
		return nil
	}
	getVersionResult, err := a.iam.GetPolicyVersion(&iam.GetPolicyVersionInput{
		PolicyArn: policyARN,
		VersionId: getResult.Policy.DefaultVersionId,
	})
	if err != nil {
		return errors.Wrapf(err, "get policy version")
	}
	currentPolicyDocument, err := url.QueryUnescape(aws.StringValue(getVersionResult.PolicyVersion.Document))
	if err != nil {
		return errors.Wrapf(err, "decoding policy document from GetPolicyVersion")
	}
	currentDocument, err := cleanPolicy([]byte(currentPolicyDocument))
	if err != nil {
		return errors.Wrapf(err, "(de)serializing policy document")
	}
	if currentDocument == document {
		log.Printf("Existing policy document for %s matches requested policy", policyName)
		return nil
	}
	log.Printf("Existing policy document for %s does not match requested policy", policyName)
	listVersionsResult, err := a.iam.ListPolicyVersions(&iam.ListPolicyVersionsInput{
		PolicyArn: policyARN,
	})
	if err != nil {
		return err
	}
	var version *iam.PolicyVersion
	for i := range listVersionsResult.Versions {
		v := listVersionsResult.Versions[i]
		if !aws.BoolValue(v.IsDefaultVersion) {
			version = v
			break
		}
	}
	if version != nil {
		// There are at least one non-default version. Delete it first to make
		// sure the limit on the number of versions is not reached.
		_, err := a.iam.DeletePolicyVersion(&iam.DeletePolicyVersionInput{
			PolicyArn: policyARN,
			VersionId: version.VersionId,
		})
		if err != nil {
			return err
		}
		log.Printf("Deleted policy version %s", aws.StringValue(version.VersionId))
	}
	createVersionResult, err := a.iam.CreatePolicyVersion(&iam.CreatePolicyVersionInput{
		PolicyArn:      policyARN,
		PolicyDocument: aws.String(string(document)),
		SetAsDefault:   aws.Bool(true),
	})
	if err != nil {
		return err
	}
	log.Printf("Created policy version %s", aws.StringValue(createVersionResult.PolicyVersion.VersionId))
	return nil
}
