# AWS Attune Pack

Production-oriented AWS infrastructure actions using current boto3 and botocore service models. This pack is a curated modernization of the Apache-2.0 [StackStorm Exchange AWS pack](https://github.com/StackStorm-Exchange/stackstorm-aws), not a mechanical conversion of its 3,583 generated action metadata files.

## Credential Profiles

Create a pack-owned Attune Key named `aws.credentials`, or pass another `credential_key`. Every profile pins an expected account and an explicit regional allowlist. The default provider chain is preferred because it supports EC2 instance roles, ECS task roles, EKS web identity, IAM Identity Center, environment credentials, and shared AWS configuration without placing long-lived keys in an action.

```json
{
  "auth_method": "default",
  "default_region": "us-east-1",
  "allowed_regions": ["us-east-1", "us-west-2"],
  "expected_account_id": "123456789012",
  "connect_timeout_seconds": 5,
  "read_timeout_seconds": 60,
  "max_artifact_bytes": 536870912
}
```

An optional `profile_name` selects a boto3 shared profile. Static credentials are supported only as an explicit fallback:

```json
{
  "auth_method": "static",
  "aws_access_key_id": "AKIA...",
  "aws_secret_access_key": "...",
  "aws_session_token": "optional-temporary-session-token",
  "default_region": "us-east-1",
  "allowed_regions": ["us-east-1"],
  "expected_account_id": "123456789012"
}
```

To assume a role, add the following fields to either source profile. The source caller must equal `source_account_id`, and the role account must equal `expected_account_id`. Role ARN, source account, External ID, session name, source identity, tags, transitive tag keys, and duration live only in the protected Attune Key, never in action parameters. Session tags are capped at 50, reserved `aws:` tags are rejected, transitive keys must name supplied tags, and credentials remain in memory.

```json
{
  "role_arn": "arn:aws:iam::123456789012:role/attune-automation",
  "source_account_id": "210987654321",
  "role_session_name": "attune-production",
  "external_id": "customer-issued-external-id",
  "source_identity": "attune",
  "duration_seconds": 3600,
  "session_tags": {"automation": "attune", "environment": "production"},
  "transitive_tag_keys": ["automation"]
}
```

The resolved caller is checked with STS before service work. A mismatch with `expected_account_id` fails before the requested operation. Grant each profile only the actions and resource ARNs it needs; action confirmation is not an IAM boundary.

## Transport And Safety

All SDK clients use the selected allowed region, bounded connect/read timeouts, botocore parameter validation, and AWS SDK endpoint resolution. Configured endpoint URL overrides and HTTP proxies are ignored, no action accepts an endpoint URL, and TLS verification cannot be disabled. The pack does not expose or log credentials, AWS error messages, signed Lambda code URLs, or Lambda environment variables.

Read operations use botocore standard retries with at most three total attempts. Mutations have no automatic retries and report `retried: false`, avoiding duplicate work after ambiguous transport failures. CloudFormation request tokens are accepted where native: `ClientRequestToken` for stack create/update/delete and `ClientToken` for change-set creation. Other mutations do not invent idempotency.

List actions use botocore paginators with `max_results`, `page_size`, and optional opaque `starting_token`. Outputs include an opaque `next_token` when truncated. Waiters and change-set polling require bounded delay and attempts. The generic dispatcher is intentionally omitted because botocore service models do not expose a universal, reliable read-only trait capable of proving that an arbitrary modeled method is non-mutating.

S3 upload and download paths are relative to `ATTUNE_ARTIFACTS_DIR`. Absolute paths, traversal, escaping symlinks, missing parents, non-files, and objects exceeding the profile byte bound are rejected. Downloads stream to a temporary file in the destination directory and atomically replace the destination only after success. Existing files require exact `OVERWRITE:<relative-path>` confirmation. Upload uses a single `PutObject` and requires `PUT:<bucket>/<key>` confirmation because an existing object may be replaced.

## Actions

### Identity And EC2

| Action | Behavior |
| --- | --- |
| `aws.sts_get_caller_identity` | Return the resolved caller account, ARN, and principal ID. |
| `aws.ec2_describe_instances` | Bounded instance discovery by IDs or filters. |
| `aws.ec2_describe_images` | Bounded AMI discovery; IDs or owners are required. |
| `aws.ec2_start_instances` | Start explicit instance IDs, once. |
| `aws.ec2_stop_instances` | Stop explicit IDs after `STOP:<sorted IDs>`. Force and skip-OS-shutdown are not exposed. |
| `aws.ec2_reboot_instances` | Reboot explicit IDs after `REBOOT:<sorted IDs>`. |
| `aws.ec2_create_tags` | Set a bounded tag map on explicit instance IDs. |
| `aws.ec2_delete_tags` | Delete exact tags after `DELETE-TAGS:<sorted IDs>`. |
| `aws.ec2_terminate_instances` | Terminate at most 20 IDs after `TERMINATE:<sorted IDs>`. |

### S3

| Action | Behavior |
| --- | --- |
| `aws.s3_list_buckets` | Return a bounded bucket list. |
| `aws.s3_list_objects` | Bounded `ListObjectsV2` pagination by bucket and prefix. |
| `aws.s3_head_object` | Read object metadata without a body. |
| `aws.s3_upload_object` | Upload one confined artifact with exact destination confirmation. |
| `aws.s3_download_object` | Atomically download one bounded object into the artifact directory. |

### CloudFormation

| Action | Behavior |
| --- | --- |
| `aws.cloudformation_validate_template` | Validate an inline template of at most 51,200 bytes. Template URLs are not accepted. |
| `aws.cloudformation_describe_stacks` | Describe one stack or bounded stack results. |
| `aws.cloudformation_list_stacks` | List bounded stack summaries by status. |
| `aws.cloudformation_create_stack` | Create after `CREATE:<stack>` with optional native request token. |
| `aws.cloudformation_update_stack` | Update after `UPDATE:<stack>` with optional native request token. |
| `aws.cloudformation_delete_stack` | Delete after `DELETE:<stack>`. |
| `aws.cloudformation_create_change_set` | Create a named CREATE or UPDATE change set. |
| `aws.cloudformation_describe_change_set` | Read bounded changes and continuation state. |
| `aws.cloudformation_execute_change_set` | Execute after `EXECUTE_CHANGE_SET:<stack>/<change-set>`. |
| `aws.cloudformation_delete_change_set` | Delete after `DELETE_CHANGE_SET:<stack>/<change-set>`. |
| `aws.cloudformation_wait_stack` | Run one allowlisted stack waiter with bounded polling. |
| `aws.cloudformation_wait_change_set` | Poll one change set to a terminal status with bounded polling. |

Create and update expose only inline templates, scalar parameters, the three documented capability acknowledgements, and native tokens. Arbitrary template URLs, role ARNs, stack policies, notification targets, and unbounded waits are not exposed. A template itself can create powerful or costly resources, so IAM scoping and review remain mandatory.

### Route 53, RDS, And Auto Scaling

| Action | Behavior |
| --- | --- |
| `aws.route53_list_hosted_zones` | List bounded hosted zones. |
| `aws.route53_list_resource_record_sets` | List bounded records in one zone. |
| `aws.route53_change_resource_record_sets` | Apply 1-1,000 CREATE, UPSERT, or DELETE changes after `CHANGE:<zone>`. |
| `aws.route53_get_change` | Read one Route 53 change status. |
| `aws.rds_describe_instances` | Describe one or bounded RDS DB instances. |
| `aws.rds_describe_clusters` | Describe one or bounded RDS DB clusters. |
| `aws.rds_start_instance` | Start one DB instance, once. |
| `aws.rds_stop_instance` | Stop one DB instance after `STOP:<identifier>`. Snapshot creation is not exposed. |
| `aws.rds_start_cluster` | Start one DB cluster, once. |
| `aws.rds_stop_cluster` | Stop one DB cluster after `STOP:<identifier>`. |
| `aws.autoscaling_describe_groups` | Describe named or bounded Auto Scaling groups. |
| `aws.autoscaling_set_desired_capacity` | Set capacity, including zero, after `SET:<group>:<capacity>`. |

Route 53 `changes` use lowercase wrapper fields and the current boto3 `ResourceRecordSet` shape inside `record_set`, for example:

```json
{
  "hosted_zone_id": "Z123456789",
  "changes": [{
    "action": "UPSERT",
    "record_set": {
      "Name": "www.example.com.",
      "Type": "A",
      "TTL": 60,
      "ResourceRecords": [{"Value": "192.0.2.10"}]
    }
  }],
  "confirm": "CHANGE:Z123456789"
}
```

### Lambda And IAM

| Action | Behavior |
| --- | --- |
| `aws.lambda_list_functions` | List bounded Lambda function metadata. |
| `aws.lambda_get_function` | Read function metadata while redacting the signed code location and environment variables. |
| `aws.lambda_invoke` | Invoke after `INVOKE:<function>` with JSON request/response capped at 1 MiB. |
| `aws.iam_list_users` | Bounded read-only user inventory. |
| `aws.iam_list_roles` | Bounded read-only role inventory. |
| `aws.iam_list_policies` | Bounded read-only local, AWS, or complete policy inventory. |
| `aws.iam_list_groups` | Bounded read-only group inventory. |
| `aws.iam_get_user` | Read one user. |
| `aws.iam_get_role` | Read one role. |

## Output Contract

Every action receives one flat JSON object on stdin and emits a structured envelope:

```json
{"operation":"sts_get_caller_identity","result":{"identity":{"account":"123456789012"}}}
```

Dates are serialized as ISO 8601, bytes as base64 objects, and SDK response metadata is reduced to the request ID. Service error bodies/messages are not returned because they may echo input or sensitive context.

## Provenance

The attributed upstream release is exactly `v2.0.2` at `cc8ff4fa335229178ec24586aff4a69f9a270ecb`, dated 2022-06-21, under Apache-2.0. Its 3,583 generated action YAML files targeted legacy boto/boto3 constraints and were not ported. The API baseline is boto3 and botocore `1.43.72`: boto3 revision `a3fc41f4709808012ad6053980a7a9422ed4d1a4` and botocore revision `6e07fe03fd69cf36c930f8c9f7cad7f7f4fd4892`, reviewed 2026-08-14. Machine-readable details are in [`SOURCE.json`](SOURCE.json), attribution is in [`NOTICE`](NOTICE), and the exact upstream license is in [`LICENSE`](LICENSE).

## Testing

Tests are deterministic, use fake clients, make no AWS calls, require no account
or credentials, and add no undeclared test dependencies. Checks against local
botocore service models run when the pack's declared runtime dependencies are
installed; they are skipped in a bare test environment while all other tests
continue to run.

```shell
python -m unittest discover -s tests -v
python -m compileall -q actions lib tests
attune --output json pack check .
attune pack test "/home/david/Codebase/attune-packs/aws" --detailed
```
