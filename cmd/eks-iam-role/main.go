package main

import (
	"io/ioutil"
	"log"

	"github.com/jessevdk/go-flags"
	"github.com/ldx/eks_iam_role/pkg/awswrapper"
)

var opts struct {
	RoleName       string `long:"role-name" description:"Name of role to ensure" env:"ROLE_NAME" required:"true"`
	PolicyName     string `long:"policy-name" description:"Name of policy that will be ensured, by default it will be same as the role name" env:"POLICY_NAME"`
	PolicyFilePath string `long:"policy-file-path" description:"Path of policy JSON file" value-name:"FILE" env:"POLICY_FILE_PATH" required:"true"`
	AWSRegion      string `long:"aws-region" description:"AWS region" env:"AWS_REGION" required:"true"`
	AWSEndpoint    string `long:"aws-endpoint" description:"AWS endpoint URL" env:"AWS_ENDPOINT" default:""`
	ClusterName    string `long:"cluster-name" description:"Get OIDC issuer from cluster for creating role, either cluster-name or oidc-issue needs to be set" env:"CLUSTER_NAME"`
	OIDCIssuer     string `long:"oidc-issuer" description:"Create role trust policy based on OIDC issuer for creating role, either cluster-name or oidc-issue needs to be set" env:"OIDC_ISSUER"`
	Namespace      string `long:"namespace" description:"Namespace of the service account for which an IAM role association will be created" env:"NAMESPACE" required:"true"`
	ServiceAccount string `long:"service-account" description:"Name of service account for which an IAM role association will be created" env:"SERVICE_ACCOUNT" required:"true"`
}

func main() {
	if _, err := flags.Parse(&opts); err != nil {
		log.Fatalf("Parsing flags: %v", err)
	}
	if opts.OIDCIssuer == "" && opts.ClusterName == "" {
		log.Fatal("Either --oidc-issuer or --cluster-name need to be set")
	}
	if opts.PolicyName == "" {
		opts.PolicyName = opts.RoleName
	}
	buf, err := ioutil.ReadFile(opts.PolicyFilePath)
	if err != nil {
		log.Fatalf("Reading policy file %q: %v", opts.PolicyFilePath, err)
	}
	aw, err := awswrapper.New(opts.AWSRegion, opts.AWSEndpoint)
	if err != nil {
		log.Fatalf("Creating awswrapper: %v", err)
	}
	trustPolicy := ""
	if opts.ClusterName != "" {
		trustPolicy, err = aw.TrustPolicyFromCluster(opts.ClusterName, opts.Namespace, opts.ServiceAccount)
		if err != nil {
			log.Fatalf("Getting trust policy: %v", err)
		}
	} else {
		trustPolicy = aw.TrustPolicyFromOIDCIssuer(opts.OIDCIssuer, opts.Namespace, opts.ServiceAccount)
	}
	if err = aw.EnsurePolicy(opts.PolicyName, buf); err != nil {
		log.Fatalf("Ensuring policy: %v", err)
	}
	if err = aw.EnsureRole(opts.RoleName, opts.PolicyName, trustPolicy); err != nil {
		log.Fatalf("Ensuring role: %v", err)
	}
	log.Printf("Success")
}
