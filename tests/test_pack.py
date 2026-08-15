from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

try:
    import boto3  # noqa: F401
    from botocore.exceptions import BotoCoreError, ClientError, WaiterError
    from botocore.session import get_session
    from botocore.validate import validate_parameters

    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False

    class BotoCoreError(Exception):
        pass

    class ClientError(Exception):
        def __init__(self, response, operation_name):
            super().__init__(operation_name)
            self.response = response
            self.operation_name = operation_name

    class WaiterError(Exception):
        pass

    class Config:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    boto3_stub = types.ModuleType("boto3")
    boto3_stub.Session = mock.Mock(side_effect=RuntimeError("boto3 is unavailable"))
    config_stub = types.ModuleType("botocore.config")
    config_stub.Config = Config
    exceptions_stub = types.ModuleType("botocore.exceptions")
    exceptions_stub.BotoCoreError = BotoCoreError
    exceptions_stub.ClientError = ClientError
    exceptions_stub.WaiterError = WaiterError
    botocore_stub = types.ModuleType("botocore")
    botocore_stub.config = config_stub
    botocore_stub.exceptions = exceptions_stub
    sys.modules.update(
        {
            "boto3": boto3_stub,
            "botocore": botocore_stub,
            "botocore.config": config_stub,
            "botocore.exceptions": exceptions_stub,
        }
    )
    get_session = None
    validate_parameters = None


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import aws_client as client  # noqa: E402


ACCOUNT = "123456789012"
SECRET = "NEVER-PRINT-THIS-SECRET"


def profile(**changes):
    value = {
        "auth_method": "default",
        "default_region": "us-east-1",
        "allowed_regions": ["us-east-1", "us-west-2"],
        "expected_account_id": ACCOUNT,
    }
    value.update(changes)
    return value


class RecordingClient:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def __getattr__(self, name):
        def call(**kwargs):
            self.calls.append((name, kwargs))
            if not self.responses:
                return {"ResponseMetadata": {"RequestId": "request-id"}}
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        return call


class FakeContext:
    def __init__(self, service_client, **profile_changes):
        self.service_client = service_client
        self.profile = profile(**profile_changes)
        self.client_calls = []

    def client(self, service, *, read_only=True, check_account=True):
        self.client_calls.append((service, read_only, check_account))
        return self.service_client


class FakePageIterator:
    def __init__(self, pages, token=None):
        self.pages = pages
        self.resume_token = token

    def __iter__(self):
        return iter(self.pages)


class FakePaginator:
    def __init__(self, pages, token=None):
        self.pages = pages
        self.token = token
        self.calls = []

    def paginate(self, **kwargs):
        self.calls.append(kwargs)
        return FakePageIterator(self.pages, self.token)


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_curated_action_inventory(self):
        expected = {
            "sts_get_caller_identity",
            "ec2_describe_instances",
            "ec2_describe_images",
            "ec2_start_instances",
            "ec2_stop_instances",
            "ec2_reboot_instances",
            "ec2_create_tags",
            "ec2_delete_tags",
            "ec2_terminate_instances",
            "s3_list_buckets",
            "s3_list_objects",
            "s3_head_object",
            "s3_upload_object",
            "s3_download_object",
            "cloudformation_validate_template",
            "cloudformation_describe_stacks",
            "cloudformation_list_stacks",
            "cloudformation_create_stack",
            "cloudformation_update_stack",
            "cloudformation_delete_stack",
            "cloudformation_create_change_set",
            "cloudformation_describe_change_set",
            "cloudformation_execute_change_set",
            "cloudformation_delete_change_set",
            "cloudformation_wait_stack",
            "cloudformation_wait_change_set",
            "route53_list_hosted_zones",
            "route53_list_resource_record_sets",
            "route53_change_resource_record_sets",
            "route53_get_change",
            "rds_describe_instances",
            "rds_describe_clusters",
            "rds_start_instance",
            "rds_stop_instance",
            "rds_start_cluster",
            "rds_stop_cluster",
            "autoscaling_describe_groups",
            "autoscaling_set_desired_capacity",
            "lambda_list_functions",
            "lambda_get_function",
            "lambda_invoke",
            "iam_list_users",
            "iam_list_roles",
            "iam_list_policies",
            "iam_list_groups",
            "iam_get_user",
            "iam_get_role",
        }
        self.assertEqual(expected, set(self.actions))
        self.assertEqual(47, len(self.actions))

    def test_flat_stdin_json_and_structured_output(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                for required in (
                    f"ref: aws.{name}",
                    "runner_type: python",
                    'runtime_version: ">=3.10"',
                    "entry_point: aws_action.py",
                    "parameter_delivery: stdin",
                    "parameter_format: json",
                    "output_format: json",
                    "default_execution_permission_set_refs: [standard]",
                    'default: "aws.credentials"',
                    "operation: {type: string, required: true}",
                    "result: {type: object, required: true}",
                ):
                    self.assertIn(required, text)
                self.assertNotRegex(
                    text,
                    r"(?m)^  (?:aws_access_key_id|aws_secret_access_key|endpoint_url|verify):",
                )

    def test_destructive_contracts_have_confirmation(self):
        names = {
            "ec2_stop_instances",
            "ec2_reboot_instances",
            "ec2_delete_tags",
            "ec2_terminate_instances",
            "s3_upload_object",
            "cloudformation_create_stack",
            "cloudformation_update_stack",
            "cloudformation_delete_stack",
            "cloudformation_execute_change_set",
            "cloudformation_delete_change_set",
            "route53_change_resource_record_sets",
            "rds_stop_instance",
            "rds_stop_cluster",
            "autoscaling_set_desired_capacity",
            "lambda_invoke",
        }
        for name in names:
            with self.subTest(action=name):
                self.assertRegex(
                    self.actions[name],
                    r"(?m)^  confirm: \{type: string,.*required: true\}",
                )

    def test_exact_provenance_and_license(self):
        source = json.loads((ROOT / "SOURCE.json").read_text(encoding="utf-8"))
        self.assertEqual("2.0.2", source["upstream"]["version"])
        self.assertEqual(
            "cc8ff4fa335229178ec24586aff4a69f9a270ecb", source["upstream"]["revision"]
        )
        self.assertEqual(3583, source["upstream"]["generated_action_metadata_files"])
        self.assertEqual("1.43.72", source["api_reference"]["boto3_version"])
        self.assertEqual("1.43.72", source["api_reference"]["botocore_version"])
        digest = hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
        self.assertEqual(
            "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1", digest
        )

    def test_readme_names_every_action_and_security_boundaries(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in self.actions:
            self.assertIn(f"`aws.{name}`", readme)
        for phrase in (
            "ATTUNE_ARTIFACTS_DIR",
            "expected_account_id",
            "External ID",
            "no automatic retries",
            "TLS verification cannot be disabled",
            "generic dispatcher",
            "no AWS calls",
        ):
            self.assertIn(phrase, readme)


class ServiceModelTests(unittest.TestCase):
    @unittest.skipUnless(
        SDK_AVAILABLE, "boto3/botocore runtime dependencies unavailable"
    )
    def test_curated_methods_exist_in_pinned_botocore_models(self):
        session = get_session()
        expected = {
            "sts": {"GetCallerIdentity", "AssumeRole"},
            "ec2": {
                "DescribeInstances",
                "DescribeImages",
                "StartInstances",
                "StopInstances",
                "RebootInstances",
                "CreateTags",
                "DeleteTags",
                "TerminateInstances",
            },
            "s3": {
                "ListBuckets",
                "ListObjectsV2",
                "HeadObject",
                "PutObject",
                "GetObject",
            },
            "cloudformation": {
                "ValidateTemplate",
                "DescribeStacks",
                "ListStacks",
                "CreateStack",
                "UpdateStack",
                "DeleteStack",
                "CreateChangeSet",
                "DescribeChangeSet",
                "ExecuteChangeSet",
                "DeleteChangeSet",
            },
            "route53": {
                "ListHostedZones",
                "ListResourceRecordSets",
                "ChangeResourceRecordSets",
                "GetChange",
            },
            "rds": {
                "DescribeDBInstances",
                "DescribeDBClusters",
                "StartDBInstance",
                "StopDBInstance",
                "StartDBCluster",
                "StopDBCluster",
            },
            "autoscaling": {"DescribeAutoScalingGroups", "SetDesiredCapacity"},
            "lambda": {"ListFunctions", "GetFunction", "Invoke"},
            "iam": {
                "ListUsers",
                "ListRoles",
                "ListPolicies",
                "ListGroups",
                "GetUser",
                "GetRole",
            },
        }
        for service, operations in expected.items():
            with self.subTest(service=service):
                model = session.get_service_model(service)
                self.assertLessEqual(operations, set(model.operation_names))

    def test_generic_dispatcher_is_intentionally_absent(self):
        self.assertFalse((ROOT / "actions" / "generic_read_only.yaml").exists())
        source = (ROOT / "lib" / "aws_client.py").read_text(encoding="utf-8")
        self.assertNotIn("getattr(client, params", source)


class ProfileAndTransportTests(unittest.TestCase):
    def test_default_and_static_profiles(self):
        default = client._profile(profile())
        self.assertEqual("default", default["auth_method"])
        static = client._profile(
            profile(
                auth_method="static",
                aws_access_key_id="AKIAEXAMPLE",
                aws_secret_access_key=SECRET,
                aws_session_token="SESSION",
            )
        )
        self.assertEqual(SECRET, static["aws_secret_access_key"])

    def test_profiles_pin_account_regions_and_reject_endpoint_controls(self):
        invalid = [
            profile(expected_account_id="123"),
            profile(allowed_regions=["us-west-2"]),
            profile(default_region="https://attacker.invalid"),
            profile(endpoint_url="https://attacker.invalid"),
            profile(verify_tls=False),
            profile(auth_method="default", aws_access_key_id="x"),
            profile(
                auth_method="static", aws_access_key_id="x", aws_secret_access_key=None
            ),
            profile(role_arn="arn:aws:iam::999999999999:role/other"),
            profile(session_tags={"team": "platform"}),
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(client.AWSPackError):
                client._profile(value)

    def test_assume_role_fields_are_bounded_and_account_pinned(self):
        value = client._profile(
            profile(
                role_arn=f"arn:aws:iam::{ACCOUNT}:role/attune",
                source_account_id="210987654321",
                role_session_name="attune-prod",
                external_id="customer-123",
                session_tags={"team": "platform"},
                transitive_tag_keys=["team"],
                source_identity="attune",
                duration_seconds=3600,
            )
        )
        self.assertEqual("customer-123", value["external_id"])
        with self.assertRaises(client.AWSPackError):
            client._profile(
                profile(
                    role_arn=f"arn:aws:iam::{ACCOUNT}:role/attune",
                    source_account_id="210987654321",
                    session_tags={"aws:reserved": "value"},
                )
            )

    def test_assume_role_checks_source_account_and_pins_all_role_inputs(self):
        source = RecordingClient(
            [
                {"Account": "210987654321"},
                {
                    "AssumedRoleUser": {
                        "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/attune/session"
                    },
                    "Credentials": {
                        "AccessKeyId": "ASIAEXAMPLE",
                        "SecretAccessKey": SECRET,
                        "SessionToken": "SESSION",
                    },
                },
            ]
        )

        class Session:
            def __init__(self, service=None):
                self.service = service
                self.client_calls = []

            def client(self, service, **kwargs):
                self.client_calls.append((service, kwargs))
                return self.service

        source_session = Session(source)
        target_session = Session()
        boto = types.SimpleNamespace(
            Session=mock.Mock(side_effect=[source_session, target_session])
        )
        context = client.AWSContext(
            profile(
                role_arn=f"arn:aws:iam::{ACCOUNT}:role/attune",
                source_account_id="210987654321",
                role_session_name="session",
                external_id="tenant-value",
                session_tags={"team": "platform"},
            ),
            boto3_module=boto,
        )
        self.assertIs(target_session, context._session)
        self.assertEqual("get_caller_identity", source.calls[0][0])
        method, request = source.calls[1]
        self.assertEqual("assume_role", method)
        self.assertEqual(f"arn:aws:iam::{ACCOUNT}:role/attune", request["RoleArn"])
        self.assertEqual("tenant-value", request["ExternalId"])
        self.assertEqual([{"Key": "team", "Value": "platform"}], request["Tags"])
        self.assertEqual(
            3, source_session.client_calls[0][1]["config"].retries["total_max_attempts"]
        )
        self.assertEqual(
            1, source_session.client_calls[1][1]["config"].retries["total_max_attempts"]
        )
        self.assertTrue(all(call[1]["verify"] for call in source_session.client_calls))

    def test_transport_pins_tls_endpoints_timeouts_and_retry_counts(self):
        value = client._profile(
            profile(connect_timeout_seconds=2, read_timeout_seconds=30)
        )
        read = client._config(value, read_only=True)
        write = client._config(value, read_only=False)
        self.assertEqual(2, read.connect_timeout)
        self.assertEqual(30, read.read_timeout)
        self.assertEqual(3, read.retries["total_max_attempts"])
        self.assertEqual(1, write.retries["total_max_attempts"])
        self.assertTrue(read.ignore_configured_endpoint_urls)
        self.assertEqual({}, read.proxies)

    def test_region_must_be_in_profile_allowlist_without_making_calls(self):
        with self.assertRaisesRegex(client.AWSPackError, "not allowed"):
            client.AWSContext(profile(), "eu-west-1")

    def test_client_error_does_not_echo_service_message_or_credentials(self):
        error = ClientError(
            {
                "Error": {"Code": "AccessDenied", "Message": SECRET},
                "ResponseMetadata": {"RequestId": "abc-123"},
            },
            "GetCallerIdentity",
        )
        with self.assertRaises(client.AWSPackError) as caught:
            client._call(RecordingClient([error]), "request", {})
        self.assertEqual("AWS AccessDenied (request abc-123)", str(caught.exception))
        self.assertNotIn(SECRET, str(caught.exception))

    def test_redaction_preserves_continuation_tokens_but_hides_credentials_and_signed_urls(
        self,
    ):
        value = client._safe(
            {
                "NextToken": "continue",
                "ClientRequestToken": "idempotency",
                "Credentials": {"AccessKeyId": SECRET},
                "Location": "https://signed.example/?secret=yes",
                "Environment": {"Variables": {"PASSWORD": SECRET}},
            }
        )
        self.assertEqual("continue", value["NextToken"])
        self.assertEqual("idempotency", value["ClientRequestToken"])
        self.assertEqual("[REDACTED]", value["Credentials"])
        self.assertEqual("[REDACTED]", value["Location"])
        self.assertEqual("[REDACTED]", value["Environment"]["Variables"])


class PaginationAndActionTests(unittest.TestCase):
    def test_pagination_is_bounded_and_returns_resume_token(self):
        paginator = FakePaginator(
            [{"Users": [{"UserName": "one"}]}, {"Users": [{"UserName": "two"}]}],
            "resume",
        )
        service = RecordingClient()
        service.get_paginator = mock.Mock(return_value=paginator)
        result = client._paginate(
            service, "list_users", "Users", {}, {"max_results": 2, "page_size": 1}
        )
        self.assertEqual(["one", "two"], [item["UserName"] for item in result["items"]])
        self.assertEqual("resume", result["pagination"]["next_token"])
        self.assertEqual(
            {"MaxItems": 2, "PageSize": 1}, paginator.calls[0]["PaginationConfig"]
        )

    def test_paginator_without_native_limit_does_not_receive_page_size(self):
        paginator = FakePaginator([{"Stacks": []}])
        paginator._pagination_cfg = {"input_token": "NextToken"}
        service = RecordingClient()
        service.get_paginator = mock.Mock(return_value=paginator)
        client._paginate(
            service,
            "describe_stacks",
            "Stacks",
            {},
            {"max_results": 5},
        )
        self.assertEqual({"MaxItems": 5}, paginator.calls[0]["PaginationConfig"])

    def test_terminate_requires_exact_confirmation_before_call(self):
        service = RecordingClient()
        context = FakeContext(service)
        params = {"instance_ids": ["i-12345678"], "confirm": "wrong"}
        with self.assertRaisesRegex(client.AWSPackError, "confirm"):
            client.execute_with_context("ec2_terminate_instances", params, context)
        self.assertEqual([], service.calls)
        params["confirm"] = "TERMINATE:i-12345678"
        result = client.execute_with_context("ec2_terminate_instances", params, context)
        self.assertTrue(result["changed"])
        self.assertEqual(
            ("terminate_instances", {"InstanceIds": ["i-12345678"]}), service.calls[0]
        )
        self.assertEqual(("ec2", False, True), context.client_calls[-1])

    @unittest.skipUnless(
        SDK_AVAILABLE, "boto3/botocore runtime dependencies unavailable"
    )
    def test_change_set_uses_native_client_token_name(self):
        service = RecordingClient([{"Id": "change-id"}])
        context = FakeContext(service)
        params = {
            "stack_name": "stack-a",
            "change_set_name": "change-a",
            "change_set_type": "UPDATE",
            "template_body": "Resources: {}",
            "client_request_token": "request-1",
        }
        client.execute_with_context("cloudformation_create_change_set", params, context)
        _, request = service.calls[0]
        self.assertEqual("request-1", request["ClientToken"])
        self.assertNotIn("ClientRequestToken", request)
        model = (
            get_session()
            .get_service_model("cloudformation")
            .operation_model("CreateChangeSet")
        )
        validate_parameters(request, model.input_shape)

    def test_route53_get_change_does_not_require_or_send_hosted_zone(self):
        service = RecordingClient(
            [{"ChangeInfo": {"Id": "/change/C1", "Status": "PENDING"}}]
        )
        client.execute_with_context(
            "route53_get_change", {"change_id": "/change/C1"}, FakeContext(service)
        )
        self.assertEqual(("get_change", {"Id": "/change/C1"}), service.calls[0])

    @unittest.skipUnless(
        SDK_AVAILABLE, "boto3/botocore runtime dependencies unavailable"
    )
    def test_route53_change_request_matches_current_service_model(self):
        service = RecordingClient([{"ChangeInfo": {"Id": "/change/C1"}}])
        params = {
            "hosted_zone_id": "Z123456789",
            "changes": [
                {
                    "action": "UPSERT",
                    "record_set": {
                        "Name": "www.example.com.",
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": "192.0.2.1"}],
                    },
                }
            ],
            "confirm": "CHANGE:Z123456789",
        }
        client.execute_with_context(
            "route53_change_resource_record_sets", params, FakeContext(service)
        )
        _, request = service.calls[0]
        model = (
            get_session()
            .get_service_model("route53")
            .operation_model("ChangeResourceRecordSets")
        )
        validate_parameters(request, model.input_shape)

    @unittest.skipUnless(
        SDK_AVAILABLE, "boto3/botocore runtime dependencies unavailable"
    )
    def test_rds_method_names_match_current_clients(self):
        service = RecordingClient()
        client.execute_with_context(
            "rds_start_instance",
            {"db_instance_identifier": "database-1"},
            FakeContext(service),
        )
        self.assertEqual("start_db_instance", service.calls[0][0])
        model = (
            get_session().get_service_model("rds").operation_model("StartDBInstance")
        )
        validate_parameters(service.calls[0][1], model.input_shape)

    def test_autoscaling_zero_capacity_requires_exact_confirmation(self):
        service = RecordingClient()
        params = {"group_name": "api", "desired_capacity": 0, "confirm": "SET:api:0"}
        result = client.execute_with_context(
            "autoscaling_set_desired_capacity", params, FakeContext(service)
        )
        self.assertTrue(result["changed"])
        self.assertEqual(0, service.calls[0][1]["DesiredCapacity"])

    def test_iam_inventory_is_read_only(self):
        paginator = FakePaginator([{"Roles": [{"RoleName": "reader"}]}])
        service = RecordingClient()
        service.get_paginator = mock.Mock(return_value=paginator)
        context = FakeContext(service)
        result = client.execute_with_context("iam_list_roles", {}, context)
        self.assertEqual("reader", result["items"][0]["RoleName"])
        self.assertEqual(("iam", True, True), context.client_calls[0])


class ArtifactTests(unittest.TestCase):
    def test_artifact_paths_reject_traversal_absolute_paths_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input.txt").write_text("safe", encoding="utf-8")
            outside = root.parent / f"{root.name}-outside"
            outside.write_text("secret", encoding="utf-8")
            (root / "link").symlink_to(outside)
            with mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}):
                _, safe = client._artifact_path("input.txt", existing=True)
                self.assertEqual(root / "input.txt", safe)
                for path in ("../outside", "sub/../input.txt", str(outside), "link"):
                    with (
                        self.subTest(path=path),
                        self.assertRaises(client.AWSPackError),
                    ):
                        client._artifact_path(path, existing=True)
            outside.unlink()

    def test_s3_download_is_bounded_atomic_and_confined(self):
        class Body(io.BytesIO):
            closed_by_pack = False

            def close(self):
                self.closed_by_pack = True
                super().close()

        body = Body(b"object-data")
        service = RecordingClient([{"Body": body, "ContentLength": 11}])
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}),
        ):
            result = client.execute_with_context(
                "s3_download_object",
                {
                    "bucket": "example-bucket",
                    "key": "key",
                    "artifact_path": "download.bin",
                },
                FakeContext(service, max_artifact_bytes=100),
            )
            self.assertEqual(
                b"object-data", (Path(directory) / "download.bin").read_bytes()
            )
        self.assertTrue(body.closed_by_pack)
        self.assertEqual(11, result["bytes"])

    def test_existing_download_requires_exact_relative_path_confirmation(self):
        service = RecordingClient()
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}),
        ):
            (Path(directory) / "existing").write_text("old", encoding="utf-8")
            with self.assertRaisesRegex(client.AWSPackError, "confirm"):
                client.execute_with_context(
                    "s3_download_object",
                    {
                        "bucket": "example-bucket",
                        "key": "key",
                        "artifact_path": "existing",
                    },
                    FakeContext(service),
                )
        self.assertEqual([], service.calls)


class CredentialAndEntryPointTests(unittest.TestCase):
    def test_fetch_key_accepts_json_object_value(self):
        parsed = types.SimpleNamespace(
            data=types.SimpleNamespace(value=json.dumps(profile()))
        )
        fake_attune = types.ModuleType("attune")
        fake_attune.context = types.SimpleNamespace(client=object())
        fake_secrets = types.ModuleType("attune.api_client.api.secrets")
        fake_secrets.get_key = types.SimpleNamespace(
            sync_detailed=mock.Mock(
                return_value=types.SimpleNamespace(status_code=200, parsed=parsed)
            )
        )
        modules = {
            "attune": fake_attune,
            "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": fake_secrets,
        }
        with mock.patch.dict(sys.modules, modules):
            self.assertEqual(
                ACCOUNT, client._fetch_key("aws.credentials")["expected_account_id"]
            )

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "aws_action_test", ROOT / "actions" / "aws_action.py"
        )
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def run_main(self, raw, error=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        patch_execute = (
            mock.patch.object(
                self.module,
                "execute_action",
                return_value={"identity": {"account": ACCOUNT}},
            )
            if error is None
            else mock.patch.object(self.module, "execute_action", side_effect=error)
        )
        with (
            patch_execute,
            mock.patch.dict(
                os.environ, {"ATTUNE_ACTION": "aws.sts_get_caller_identity"}
            ),
            mock.patch("sys.stdin", io.StringIO(raw)),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            code = self.module.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_entrypoint_output_and_secret_safe_errors(self):
        code, stdout, stderr = self.run_main("{}")
        self.assertEqual(0, code)
        self.assertEqual("sts_get_caller_identity", json.loads(stdout)["operation"])
        self.assertEqual("", stderr)
        for raw, error in (
            ("[]", None),
            ("{}", RuntimeError(SECRET)),
            ('{"broken":', None),
        ):
            code, stdout, stderr = self.run_main(raw, error)
            self.assertEqual(1, code)
            self.assertEqual("", stdout)
            self.assertNotIn(SECRET, stderr)


if __name__ == "__main__":
    unittest.main()
