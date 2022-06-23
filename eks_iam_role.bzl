def _runfiles(ctx, tgt):
    print(tgt.files.to_list()[0])
    f = tgt.files.to_list()[0]
    return f.short_path
    if ctx.workspace_name:
        return "${RUNFILES}/%s" % (ctx.workspace_name + "/" + f.short_path)
    else:
        return "${RUNFILES}/%s" % f.short_path

def _eks_iam_role(ctx):
    print(ctx)
    tool_as_list = [ctx.attr.tool]
    tool_inputs, tools_input_mfs = ctx.resolve_tools(tools = tool_as_list)

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

    runfiles_path = "$0.runfiles/"
    doc_file_root = runfiles_path + ctx.workspace_name + "/"
    #doc_file_path = doc_file_root + ctx.files.policy_document[0].path
    #doc_file_path = _runfiles(ctx, ctx.attr.policy_document)
    doc_file_path = "/home/vilmos/Projects/go/src/github.com/ldx/rules_eks_iam_role/examples/s3.json"

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

    out = ctx.actions.declare_file(ctx.label.name)
    #ctx.actions.write(
    #    output = out,
    #    content = "%s %s" % (ctx.executable.tool, " ".join(args)),
    #)

    ctx.actions.run(
        tools = tool_inputs,
        executable = ctx.executable.tool,
        arguments = args,
        mnemonic = "EKSIAMRole",
        use_default_shell_env = False,
        input_manifests = tools_input_mfs,
        outputs = [out],
    )

    return DefaultInfo(
        executable = ctx.outputs.executable,
        files = depset([out]),
        #runfiles = ctx.runfiles(files = [out]),
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
