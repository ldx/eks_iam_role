# Eks-iam-role

This program creates or updates [IAM roles for service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html). The IAM role can then be associated to a Kubernetes service account via a service account token that is automounted into pods, thus pods can assume the role.

## Use case

Eks-iam-role is a simple and lightweight alternative to `eksctl create iamserviceaccount` that works in an idempotent way: you can run it multiple times with the same arguments, or change the policy file, and `eks-iam-role` will ensure that the IAM policy is up to date, it is attached to the IAM role (which is created if necessary), and it is associated with the right service account.

Please note that `eks-iam-role` will not create the Kubernetes namespace, service account or set up RBAC for it. That can be done the usual way via Kubernetes manifests.

## Build

Install [Bazelisk](https://github.com/bazelbuild/bazelisk), then:

    bazel build //...

This will build the main binary.

Note: the first build might take a while since it needs to download the right Go toolchain.

## Install

If you want to install the built binary in your PATH, look up the output from the build:

    bazel cquery --output=files //cmd/eks-iam-role:eks-iam-role
    INFO: Analyzed target //cmd/eks-iam-role:eks-iam-role (0 packages loaded, 0 targets configured).
    INFO: Found 1 target...
    bazel-out/k8-fastbuild/bin/cmd/eks-iam-role/eks-iam-role_/eks-iam-role
    INFO: Elapsed time: 0.385s
    INFO: 0 processes.
    INFO: Build completed successfully, 0 total actions

The output `bazel-out/k8-fastbuild/bin/cmd/eks-iam-role/eks-iam-role_/eks-iam-role` is a static binary that can be copied to another directory.

## Usage

You need an IAM policy in a file. An example can be found in [examples/s3.json](examples/s3.json).

To create a policy from this file, a role, and associate the role with a service account in a namespace:

    bazel run //cmd/eks-iam-role -- --aws-region <my-aws-region> --role-name <my-role> --policy-file-path=$(pwd)/examples/s3.json --namespace <my-namespace> --service-account <my-service-account-name> --oidc-issuer <my-oidc-issuer>

To get the OIDC issuer of an EKS cluster:

    aws --region <region> eks describe-cluster --name <cluster-name> --query "cluster.identity.oidc.issuer" --output text

You can also have `eks-iam-role` look up the OIDC issuer via supplying the name of the EKS cluster:

    bazel run //cmd/eks-iam-role -- --aws-region <my-aws-region> --role-name <my-role> --policy-file-path=$(pwd)/examples/s3.json --namespace <my-namespace> --service-account <my-service-account-name> --cluster-name <my-cluster>

Use

    bazel run //cmd/eks-iam-role -- --help

to get the list of all command line arguments.
