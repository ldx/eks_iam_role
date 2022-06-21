package awswrapper

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/eks/eksiface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/stretchr/testify/assert"
)

type mockedEKSAPI struct {
	eksiface.EKSAPI
	resp *eks.DescribeClusterOutput
	err  error
}

func (m mockedEKSAPI) DescribeCluster(in *eks.DescribeClusterInput) (*eks.DescribeClusterOutput, error) {
	return m.resp, m.err
}

type mockedIAMAPI struct {
	iamiface.IAMAPI
	attachRolePolicyErr         error
	attachRolePolicyOut         *iam.AttachRolePolicyOutput
	createPolicyErr             error
	createPolicyOut             *iam.CreatePolicyOutput
	createPolicyVersionErr      error
	createPolicyVersionOut      *iam.CreatePolicyVersionOutput
	createRoleErr               error
	createRoleOut               *iam.CreateRoleOutput
	deletePolicyVersionErr      error
	deletePolicyVersionOut      *iam.DeletePolicyVersionOutput
	getPolicyErr                error
	getPolicyOut                *iam.GetPolicyOutput
	getPolicyVersionErr         error
	getPolicyVersionOut         *iam.GetPolicyVersionOutput
	getRoleErr                  error
	getRoleOut                  *iam.GetRoleOutput
	listAttachedRolePoliciesErr error
	listAttachedRolePoliciesOut *iam.ListAttachedRolePoliciesOutput
	listPolicyVersionsErr       error
	listPolicyVersionsOut       *iam.ListPolicyVersionsOutput
}

func (m mockedIAMAPI) AttachRolePolicy(in *iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
	return m.attachRolePolicyOut, m.attachRolePolicyErr
}

func (m mockedIAMAPI) CreatePolicy(in *iam.CreatePolicyInput) (*iam.CreatePolicyOutput, error) {
	return m.createPolicyOut, m.createPolicyErr
}

func (m mockedIAMAPI) CreateRole(in *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	return m.createRoleOut, m.createRoleErr
}

func (m mockedIAMAPI) CreatePolicyVersion(in *iam.CreatePolicyVersionInput) (*iam.CreatePolicyVersionOutput, error) {
	return m.createPolicyVersionOut, m.createPolicyVersionErr
}

func (m mockedIAMAPI) DeletePolicyVersion(in *iam.DeletePolicyVersionInput) (*iam.DeletePolicyVersionOutput, error) {
	return m.deletePolicyVersionOut, m.deletePolicyVersionErr
}

func (m mockedIAMAPI) GetPolicy(in *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
	return m.getPolicyOut, m.getPolicyErr
}

func (m mockedIAMAPI) GetRole(in *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	return m.getRoleOut, m.getRoleErr
}

func (m mockedIAMAPI) GetPolicyVersion(in *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
	return m.getPolicyVersionOut, m.getPolicyVersionErr
}

func (m mockedIAMAPI) ListAttachedRolePolicies(in *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
	return m.listAttachedRolePoliciesOut, m.listAttachedRolePoliciesErr
}

func (m mockedIAMAPI) ListPolicyVersions(in *iam.ListPolicyVersionsInput) (*iam.ListPolicyVersionsOutput, error) {
	return m.listPolicyVersionsOut, m.listPolicyVersionsErr
}

func TestEnsurePolicy(t *testing.T) {
	testCases := []struct {
		mock *mockedIAMAPI
		err  bool
		name string
		doc  string
	}{
		// Invalid document.
		{
			mock: &mockedIAMAPI{},
			err:  true,
			name: "my-policy-0",
			doc:  "invalid document",
		},
		// Policy does not exist.
		{
			mock: &mockedIAMAPI{
				createPolicyOut: &iam.CreatePolicyOutput{
					Policy: &iam.Policy{
						DefaultVersionId: aws.String("my-version"),
					},
				},
				getPolicyErr: awserr.New(iam.ErrCodeNoSuchEntityException, "", nil),
			},
			err:  false,
			name: "my-policy-1",
			doc:  "{}",
		},
		{
			mock: &mockedIAMAPI{
				getPolicyErr: fmt.Errorf("GetPolicy test error"),
			},
			err:  true,
			name: "my-policy-1-err-0",
			doc:  "{}",
		},
		{
			mock: &mockedIAMAPI{
				createPolicyErr: fmt.Errorf("CreatePolicy test error"),
				getPolicyErr:    awserr.New(iam.ErrCodeNoSuchEntityException, "", nil),
			},
			err:  true,
			name: "my-policy-1-err-1",
			doc:  "{}",
		},
		// Policy default version already exists and document matches.
		{
			mock: &mockedIAMAPI{
				getPolicyOut: &iam.GetPolicyOutput{
					Policy: &iam.Policy{
						DefaultVersionId: aws.String("my-existing-version"),
					},
				},
				getPolicyVersionOut: &iam.GetPolicyVersionOutput{
					PolicyVersion: &iam.PolicyVersion{
						Document: aws.String("%7B%7D"), // URL encoded {}
					},
				},
			},
			err:  false,
			name: "my-policy-2",
			doc:  "{}",
		},
		{
			mock: &mockedIAMAPI{
				getPolicyOut: &iam.GetPolicyOutput{
					Policy: &iam.Policy{
						DefaultVersionId: aws.String("my-existing-version"),
					},
				},
				getPolicyVersionErr: fmt.Errorf("GetPolicyVersion test error"),
			},
			err:  true,
			name: "my-policy-2-err-1",
			doc:  "{}",
		},
		// Policy default version already exists as the only version and document has changed.
		{
			mock: &mockedIAMAPI{
				createPolicyVersionOut: &iam.CreatePolicyVersionOutput{
					PolicyVersion: &iam.PolicyVersion{
						VersionId: aws.String("my-new-version"),
					},
				},
				getPolicyOut: &iam.GetPolicyOutput{
					Policy: &iam.Policy{
						DefaultVersionId: aws.String("my-default-version"),
					},
				},
				getPolicyVersionOut: &iam.GetPolicyVersionOutput{
					PolicyVersion: &iam.PolicyVersion{
						Document: aws.String("%7B%22version%22%3A%20%22policy-version%22%7D"),
					},
				},
				listPolicyVersionsOut: &iam.ListPolicyVersionsOutput{
					Versions: []*iam.PolicyVersion{
						{
							IsDefaultVersion: aws.Bool(true),
							VersionId:        aws.String("my-default-version"),
						},
					},
				},
			},
			err:  false,
			name: "my-policy-3",
			doc:  "{}",
		},
		{
			mock: &mockedIAMAPI{
				createPolicyVersionOut: &iam.CreatePolicyVersionOutput{
					PolicyVersion: &iam.PolicyVersion{
						VersionId: aws.String("my-new-version"),
					},
				},
				getPolicyOut: &iam.GetPolicyOutput{
					Policy: &iam.Policy{
						DefaultVersionId: aws.String("my-default-version"),
					},
				},
				getPolicyVersionOut: &iam.GetPolicyVersionOutput{
					PolicyVersion: &iam.PolicyVersion{
						Document: aws.String("%7B%22version%22%3A%20%22policy-version%22%7D"),
					},
				},
				listPolicyVersionsErr: fmt.Errorf("ListPolicyVersions test error"),
			},
			err:  true,
			name: "my-policy-3-err-0",
			doc:  "{}",
		},
		{
			mock: &mockedIAMAPI{
				getPolicyOut: &iam.GetPolicyOutput{
					Policy: &iam.Policy{
						DefaultVersionId: aws.String("my-default-version"),
					},
				},
				getPolicyVersionErr: fmt.Errorf("GetPolicyVersion test error"),
			},
			err:  true,
			name: "my-policy-3-err-1",
			doc:  "{}",
		},
		{
			mock: &mockedIAMAPI{
				createPolicyVersionErr: fmt.Errorf("CreatePolicyVersion test error"),
				getPolicyOut: &iam.GetPolicyOutput{
					Policy: &iam.Policy{
						DefaultVersionId: aws.String("my-default-version"),
					},
				},
				getPolicyVersionOut: &iam.GetPolicyVersionOutput{
					PolicyVersion: &iam.PolicyVersion{
						Document: aws.String("%7B%22version%22%3A%20%22policy-version%22%7D"),
					},
				},
				listPolicyVersionsOut: &iam.ListPolicyVersionsOutput{
					Versions: []*iam.PolicyVersion{
						{
							IsDefaultVersion: aws.Bool(true),
							VersionId:        aws.String("my-default-version"),
						},
					},
				},
			},
			err:  true,
			name: "my-policy-3-err-2",
			doc:  "{}",
		},
		// Policy default version already exists, with multiple versions, and document has changed.
		{
			mock: &mockedIAMAPI{
				createPolicyVersionOut: &iam.CreatePolicyVersionOutput{
					PolicyVersion: &iam.PolicyVersion{
						VersionId: aws.String("my-new-version"),
					},
				},
				deletePolicyVersionOut: &iam.DeletePolicyVersionOutput{},
				getPolicyOut: &iam.GetPolicyOutput{
					Policy: &iam.Policy{
						DefaultVersionId: aws.String("my-default-version"),
					},
				},
				getPolicyVersionOut: &iam.GetPolicyVersionOutput{
					PolicyVersion: &iam.PolicyVersion{
						Document: aws.String("%7B%22version%22%3A%20%22policy-version%22%7D"),
					},
				},
				listPolicyVersionsOut: &iam.ListPolicyVersionsOutput{
					Versions: []*iam.PolicyVersion{
						{
							IsDefaultVersion: aws.Bool(true),
							VersionId:        aws.String("my-default-version"),
						},
						{
							IsDefaultVersion: aws.Bool(false),
							VersionId:        aws.String("my-old-version"),
						},
					},
				},
			},
			err:  false,
			name: "my-policy-4",
			doc:  "{}",
		},
		{
			mock: &mockedIAMAPI{
				createPolicyVersionOut: &iam.CreatePolicyVersionOutput{
					PolicyVersion: &iam.PolicyVersion{
						VersionId: aws.String("my-new-version"),
					},
				},
				deletePolicyVersionErr: fmt.Errorf("DeletePolicyVersion test error"),
				getPolicyOut: &iam.GetPolicyOutput{
					Policy: &iam.Policy{
						DefaultVersionId: aws.String("my-default-version"),
					},
				},
				getPolicyVersionOut: &iam.GetPolicyVersionOutput{
					PolicyVersion: &iam.PolicyVersion{
						Document: aws.String("%7B%22version%22%3A%20%22policy-version%22%7D"),
					},
				},
				listPolicyVersionsOut: &iam.ListPolicyVersionsOutput{
					Versions: []*iam.PolicyVersion{
						{
							IsDefaultVersion: aws.Bool(true),
							VersionId:        aws.String("my-default-version"),
						},
						{
							IsDefaultVersion: aws.Bool(false),
							VersionId:        aws.String("my-old-version"),
						},
					},
				},
			},
			err:  true,
			name: "my-policy-4-err-0",
			doc:  "{}",
		},
	}
	for _, tc := range testCases {
		aw := awsWrapper{iam: tc.mock}
		err := aw.EnsurePolicy(tc.name, []byte(tc.doc))
		if tc.err {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestEnsureRole(t *testing.T) {
	// TODO: tests for EnsureRole(roleName string, policyName, trustPolicy string) error
}

func TestTrustPolicyFromCluster(t *testing.T) {
	aw := awsWrapper{
		eks: &mockedEKSAPI{
			resp: &eks.DescribeClusterOutput{
				Cluster: &eks.Cluster{
					Identity: &eks.Identity{
						Oidc: &eks.OIDC{
							Issuer: aws.String("my-issuer"),
						},
					},
				},
			},
			err: nil,
		},
	}
	policy, err := aw.TrustPolicyFromCluster("my-cluster", "my-namespace", "my-service-account")
	assert.NoError(t, err)
	assert.NotEmpty(t, policy)
	assert.Contains(t, policy, "my-issuer")
	assert.Contains(t, policy, "my-namespace")
	assert.Contains(t, policy, "my-service-account")
	j := make(map[string]interface{})
	err = json.Unmarshal([]byte(policy), &j)
	assert.NoError(t, err)
	aw.eks = &mockedEKSAPI{
		resp: nil,
		err:  fmt.Errorf("DescribeCluster test error"),
	}
	policy, err = aw.TrustPolicyFromCluster("my-cluster", "my-namespace", "my-service-account")
	assert.Error(t, err)
	assert.Empty(t, policy)
}

func TestTrustPolicyFromOIDCIssuer(t *testing.T) {
	aw := awsWrapper{}
	policy := aw.TrustPolicyFromOIDCIssuer("my-issuer", "my-namespace", "my-service-account")
	assert.NotEmpty(t, policy)
	assert.Contains(t, policy, "my-issuer")
	assert.Contains(t, policy, "my-namespace")
	assert.Contains(t, policy, "my-service-account")
	j := make(map[string]interface{})
	err := json.Unmarshal([]byte(policy), &j)
	assert.NoError(t, err)
}
