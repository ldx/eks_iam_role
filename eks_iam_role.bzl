def _eks_iam_role(ctx):
    if not ctx.attr.cluster_name and not ctx.attr.oidc_issuer:
        fail("Either cluster_name or oidc_issuer must be specified")

    role_name = ctx.attr.role_name
    if not role_name:
        role_name = ctx.attr.name

    policy_name = ctx.attr.policy_name
    if not policy_name:
        policy_name = role_name

    aws_region = ctx.attr.aws_region
    if not aws_region:
        aws_region = "us-east-1"

    doc_file_path = ctx.attr.policy_document.files.to_list()[0].short_path

    args = [
        "--aws-region",
        aws_region,
        "--role-name",
        role_name,
        "--policy-name",
        policy_name,
        "--policy-file-path",
        doc_file_path,
        "--namespace",
        ctx.attr.namespace,
        "--service-account",
        ctx.attr.service_account,
    ]
    if ctx.attr.aws_endpoint:
        args.extend(["--aws-endpoint", ctx.attr.aws_endpoint])
    if ctx.attr.cluster_name:
        args.extend(["--cluster-name", ctx.attr.cluster_name])
    if ctx.attr.oidc_issuer:
        args.extend(["--oidc-issuer", ctx.attr.oidc_issuer])

    ctx.actions.write(
        output = ctx.outputs.executable,
        content = "%s %s" % (ctx.executable.tool.short_path, " ".join(args)),
        is_executable = True,
    )

    return DefaultInfo(
        executable = ctx.outputs.executable,
        runfiles = ctx.runfiles(files = ctx.attr.policy_document.files.to_list() + [ctx.executable.tool]),
    )

eks_iam_role = rule(
    attrs = {
        "role_name": attr.string(),
        "policy_name": attr.string(),
        "policy_document": attr.label(
            mandatory = True,
            allow_files = True,
        ),
        "aws_region": attr.string(),
        "aws_endpoint": attr.string(),
        "cluster_name": attr.string(),
        "oidc_issuer": attr.string(),
        "namespace": attr.string(mandatory=True),
        "service_account": attr.string(mandatory=True),
        "tool": attr.label(
            default = Label("//cmd/eks-iam-role:eks-iam-role"),
            executable = True,
            allow_files = True,
            cfg = "exec",
        ),
    },
    executable = True,
    implementation = _eks_iam_role,
)
