"""Guarded boto3 session, transport, and action implementation."""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
import time
from datetime import date, datetime
from decimal import Decimal
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, WaiterError


class AWSPackError(Exception):
    """An expected, safely reportable pack failure."""


_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d+$")
_ACCOUNT_RE = re.compile(r"^\d{12}$")
_ROLE_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}$"
)
_SESSION_RE = re.compile(r"^[A-Za-z0-9+=,.@_-]{2,64}$")
_INSTANCE_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
_SECRET_KEYS = {
    "accesskeyid",
    "secretaccesskey",
    "sessiontoken",
    "password",
    "secret",
    "token",
    "credentials",
    "authorization",
    "webidentitytoken",
    "securitytoken",
    "clientsecret",
    "refreshtoken",
    "idtoken",
    "location",
    "variables",
}
_PROFILE_SECRET_KEYS = {
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "external_id",
}
_MUTATIONS = {
    "ec2_start_instances",
    "ec2_stop_instances",
    "ec2_reboot_instances",
    "ec2_create_tags",
    "ec2_delete_tags",
    "ec2_terminate_instances",
    "s3_upload_object",
    "cloudformation_create_stack",
    "cloudformation_update_stack",
    "cloudformation_delete_stack",
    "cloudformation_create_change_set",
    "cloudformation_execute_change_set",
    "cloudformation_delete_change_set",
    "route53_change_resource_record_sets",
    "rds_start_instance",
    "rds_stop_instance",
    "rds_start_cluster",
    "rds_stop_cluster",
    "autoscaling_set_desired_capacity",
    "lambda_invoke",
}


def _fetch_key(ref: str) -> dict[str, Any]:
    if not isinstance(ref, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}", ref
    ):
        raise AWSPackError("credential_key is invalid")
    try:
        from attune import context
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(client=context.client, ref=ref)
        if response.status_code != 200 or response.parsed is None:
            raise AWSPackError("credential key is unavailable")
        value = response.parsed.data.value
        value = json.loads(value) if isinstance(value, str) else value
    except AWSPackError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AWSPackError("credential key is unavailable") from exc
    if not isinstance(value, dict):
        raise AWSPackError("credential key value must be a JSON object")
    return value


def _bounded_number(value: Any, name: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AWSPackError(f"{name} must be a number")
    value = float(value)
    if not low <= value <= high:
        raise AWSPackError(f"{name} must be between {low:g} and {high:g}")
    return value


def _profile(raw: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "auth_method",
        "profile_name",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "default_region",
        "allowed_regions",
        "expected_account_id",
        "source_account_id",
        "role_arn",
        "role_session_name",
        "external_id",
        "duration_seconds",
        "session_tags",
        "transitive_tag_keys",
        "source_identity",
        "connect_timeout_seconds",
        "read_timeout_seconds",
        "max_artifact_bytes",
    }
    unknown = set(raw) - allowed
    if unknown:
        raise AWSPackError("credential profile contains unsupported fields")
    auth = raw.get("auth_method", "default")
    if auth not in {"default", "static"}:
        raise AWSPackError("auth_method must be default or static")
    default_region = raw.get("default_region")
    regions = raw.get("allowed_regions")
    if not isinstance(default_region, str) or not _REGION_RE.fullmatch(default_region):
        raise AWSPackError("default_region is required and invalid")
    if not isinstance(regions, list) or not regions or len(regions) > 50:
        raise AWSPackError("allowed_regions must contain 1-50 regions")
    if any(
        not isinstance(item, str) or not _REGION_RE.fullmatch(item) for item in regions
    ):
        raise AWSPackError("allowed_regions contains an invalid region")
    if len(set(regions)) != len(regions) or default_region not in regions:
        raise AWSPackError("allowed_regions must be unique and include default_region")
    account = raw.get("expected_account_id")
    if not isinstance(account, str) or not _ACCOUNT_RE.fullmatch(account):
        raise AWSPackError("expected_account_id is required and must contain 12 digits")
    profile_name = raw.get("profile_name")
    static_fields = (raw.get("aws_access_key_id"), raw.get("aws_secret_access_key"))
    if auth == "default":
        if any(static_fields) or raw.get("aws_session_token"):
            raise AWSPackError("static credentials require auth_method static")
        if profile_name is not None and (
            not isinstance(profile_name, str)
            or not re.fullmatch(r"[A-Za-z0-9_.@+-]{1,128}", profile_name)
        ):
            raise AWSPackError("profile_name is invalid")
    else:
        if profile_name is not None:
            raise AWSPackError(
                "profile_name cannot be combined with static credentials"
            )
        if not all(isinstance(value, str) and value for value in static_fields):
            raise AWSPackError(
                "static credentials require access key ID and secret access key"
            )
    role_arn = raw.get("role_arn")
    role_match = _ROLE_ARN_RE.fullmatch(role_arn) if isinstance(role_arn, str) else None
    if role_arn is not None and (not role_match or role_match.group(2) != account):
        raise AWSPackError("role_arn must target expected_account_id")
    if role_arn:
        source_account = raw.get("source_account_id")
        if not isinstance(source_account, str) or not _ACCOUNT_RE.fullmatch(
            source_account
        ):
            raise AWSPackError("source_account_id is required for assume-role profiles")
        session_name = raw.get("role_session_name", "attune-aws")
        if not isinstance(session_name, str) or not _SESSION_RE.fullmatch(session_name):
            raise AWSPackError("role_session_name is invalid")
        external_id = raw.get("external_id")
        if external_id is not None and (
            not isinstance(external_id, str)
            or not 2 <= len(external_id) <= 1224
            or not re.fullmatch(r"[A-Za-z0-9+=,.@:/_-]+", external_id)
        ):
            raise AWSPackError("external_id is invalid")
        tags = raw.get("session_tags", {})
        if not isinstance(tags, dict) or len(tags) > 50:
            raise AWSPackError("session_tags must be an object with at most 50 entries")
        if any(
            not isinstance(key, str)
            or not 1 <= len(key) <= 128
            or not isinstance(value, str)
            or len(value) > 256
            or key.lower().startswith("aws:")
            for key, value in tags.items()
        ):
            raise AWSPackError("session_tags contains an invalid entry")
        transitive = raw.get("transitive_tag_keys", [])
        if (
            not isinstance(transitive, list)
            or any(not isinstance(key, str) for key in transitive)
            or len(set(transitive)) != len(transitive)
            or not set(transitive) <= set(tags)
        ):
            raise AWSPackError(
                "transitive_tag_keys must be unique keys from session_tags"
            )
        if len({key.lower() for key in tags}) != len(tags):
            raise AWSPackError("session_tags keys must be case-insensitively unique")
        source = raw.get("source_identity")
        if source is not None and (
            not isinstance(source, str)
            or not _SESSION_RE.fullmatch(source)
            or source.lower().startswith("aws:")
        ):
            raise AWSPackError("source_identity is invalid")
    else:
        assume_only = {
            "role_session_name",
            "external_id",
            "duration_seconds",
            "session_tags",
            "transitive_tag_keys",
            "source_identity",
            "source_account_id",
        }
        if set(raw) & assume_only:
            raise AWSPackError("assume-role fields require role_arn")
    result = dict(raw)
    result["auth_method"] = auth
    result["connect_timeout_seconds"] = _bounded_number(
        raw.get("connect_timeout_seconds", 5), "connect_timeout_seconds", 1, 30
    )
    result["read_timeout_seconds"] = _bounded_number(
        raw.get("read_timeout_seconds", 60), "read_timeout_seconds", 1, 120
    )
    result["max_artifact_bytes"] = int(
        _bounded_number(
            raw.get("max_artifact_bytes", 536870912),
            "max_artifact_bytes",
            1,
            5368709120,
        )
    )
    return result


def _config(profile: dict[str, Any], *, read_only: bool) -> Config:
    return Config(
        connect_timeout=profile["connect_timeout_seconds"],
        read_timeout=profile["read_timeout_seconds"],
        retries={"mode": "standard", "total_max_attempts": 3 if read_only else 1},
        parameter_validation=True,
        user_agent_extra="attune-aws-pack/1.0.0",
        ignore_configured_endpoint_urls=True,
        proxies={},
        tcp_keepalive=True,
    )


class AWSContext:
    """One credential profile and its lazily created, account-pinned clients."""

    def __init__(
        self,
        profile: dict[str, Any],
        region: str | None = None,
        *,
        boto3_module: Any = boto3,
    ):
        self.profile = _profile(profile)
        selected = region or self.profile["default_region"]
        if selected not in self.profile["allowed_regions"]:
            raise AWSPackError("region is not allowed by the credential profile")
        self.region = selected
        kwargs: dict[str, Any] = {"region_name": selected}
        if self.profile["auth_method"] == "default":
            if self.profile.get("profile_name"):
                kwargs["profile_name"] = self.profile["profile_name"]
        else:
            kwargs.update(
                aws_access_key_id=self.profile["aws_access_key_id"],
                aws_secret_access_key=self.profile["aws_secret_access_key"],
            )
            if self.profile.get("aws_session_token"):
                kwargs["aws_session_token"] = self.profile["aws_session_token"]
        source_session = boto3_module.Session(**kwargs)
        self._boto3 = boto3_module
        self._session = (
            self._assume(source_session)
            if self.profile.get("role_arn")
            else source_session
        )
        self._account_checked = False

    def _assume(self, session: Any) -> Any:
        source_sts = session.client(
            "sts",
            region_name=self.region,
            config=_config(self.profile, read_only=True),
            verify=True,
        )
        source_identity = _call(source_sts, "get_caller_identity", {})
        if source_identity.get("Account") != self.profile["source_account_id"]:
            raise AWSPackError("source credentials do not match source_account_id")
        sts = session.client(
            "sts",
            region_name=self.region,
            config=_config(self.profile, read_only=False),
            verify=True,
        )
        request: dict[str, Any] = {
            "RoleArn": self.profile["role_arn"],
            "RoleSessionName": self.profile.get("role_session_name", "attune-aws"),
            "DurationSeconds": int(
                _bounded_number(
                    self.profile.get("duration_seconds", 3600),
                    "duration_seconds",
                    900,
                    43200,
                )
            ),
        }
        mapping = {"external_id": "ExternalId", "source_identity": "SourceIdentity"}
        for source, target in mapping.items():
            if self.profile.get(source):
                request[target] = self.profile[source]
        if self.profile.get("session_tags"):
            request["Tags"] = [
                {"Key": key, "Value": value}
                for key, value in self.profile["session_tags"].items()
            ]
        if self.profile.get("transitive_tag_keys"):
            request["TransitiveTagKeys"] = self.profile["transitive_tag_keys"]
        response = _call(sts, "assume_role", request)
        assumed_arn = response.get("AssumedRoleUser", {}).get("Arn", "")
        if f"::{self.profile['expected_account_id']}:assumed-role/" not in assumed_arn:
            raise AWSPackError("assume-role response did not match expected_account_id")
        credentials = response.get("Credentials", {})
        if not all(
            credentials.get(key)
            for key in ("AccessKeyId", "SecretAccessKey", "SessionToken")
        ):
            raise AWSPackError("assume-role response did not contain credentials")
        return self._boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=self.region,
        )

    def client(
        self, service: str, *, read_only: bool = True, check_account: bool = True
    ) -> Any:
        client = self._session.client(
            service,
            region_name=self.region,
            config=_config(self.profile, read_only=read_only),
            verify=True,
        )
        if check_account and not self._account_checked:
            identity = _call(
                self._session.client(
                    "sts",
                    region_name=self.region,
                    config=_config(self.profile, read_only=True),
                    verify=True,
                ),
                "get_caller_identity",
                {},
            )
            if identity.get("Account") != self.profile["expected_account_id"]:
                raise AWSPackError(
                    "resolved credentials do not match expected_account_id"
                )
            self._account_checked = True
        return client


def _call(client: Any, method: str, kwargs: dict[str, Any]) -> dict[str, Any]:
    try:
        response = getattr(client, method)(**kwargs)
    except ClientError as exc:
        error = exc.response.get("Error", {}) if isinstance(exc.response, dict) else {}
        code = re.sub(
            r"[^A-Za-z0-9_.-]", "", str(error.get("Code", "AWSServiceError"))
        )[:128]
        metadata = (
            exc.response.get("ResponseMetadata", {})
            if isinstance(exc.response, dict)
            else {}
        )
        request_id = re.sub(r"[^A-Za-z0-9-]", "", str(metadata.get("RequestId", "")))[
            :128
        ]
        suffix = f" (request {request_id})" if request_id else ""
        raise AWSPackError(f"AWS {code}{suffix}") from exc
    except (BotoCoreError, OSError) as exc:
        raise AWSPackError(f"AWS transport failed: {type(exc).__name__}") from exc
    if not isinstance(response, dict):
        raise AWSPackError("AWS returned an unexpected response")
    return response


def _safe(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            result[key] = (
                "[REDACTED]" if normalized in _SECRET_KEYS else _safe(item, secrets)
            )
        return result
    if isinstance(value, (list, tuple)):
        return [_safe(item, secrets) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return {"encoding": "base64", "data": base64.b64encode(value).decode("ascii")}
    if isinstance(value, str):
        result = value
        for secret in secrets:
            if secret:
                result = result.replace(secret, "[REDACTED]")
        return result
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _result(response: dict[str, Any], **extra: Any) -> dict[str, Any]:
    metadata = response.get("ResponseMetadata", {})
    body = {key: value for key, value in response.items() if key != "ResponseMetadata"}
    output = {**extra, "data": body}
    if metadata.get("RequestId"):
        output["request_id"] = metadata["RequestId"]
    return output


def _list(value: Any, name: str, *, minimum: int = 1, maximum: int = 100) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise AWSPackError(f"{name} must contain {minimum}-{maximum} items")
    return value


def _strings(
    value: Any, name: str, *, maximum: int = 100, pattern: re.Pattern[str] | None = None
) -> list[str]:
    items = _list(value, name, maximum=maximum)
    if any(
        not isinstance(item, str)
        or not item
        or (pattern and not pattern.fullmatch(item))
        for item in items
    ):
        raise AWSPackError(f"{name} contains an invalid value")
    if len(set(items)) != len(items):
        raise AWSPackError(f"{name} must not contain duplicates")
    return items


def _positive(value: Any, name: str, default: int, maximum: int) -> int:
    value = default if value is None else value
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise AWSPackError(f"{name} must be between 1 and {maximum}")
    return value


def _paginate(
    client: Any,
    method: str,
    result_key: str,
    kwargs: dict[str, Any],
    params: dict[str, Any],
    *,
    maximum: int = 1000,
    include_page_size: bool = True,
    minimum_page_size: int = 1,
) -> dict[str, Any]:
    limit = _positive(params.get("max_results"), "max_results", 100, maximum)
    default_page_size = max(minimum_page_size, min(100, limit))
    page_size = _positive(
        params.get("page_size"),
        "page_size",
        default_page_size,
        min(1000, maximum),
    )
    if page_size < minimum_page_size:
        raise AWSPackError(f"page_size must be at least {minimum_page_size}")
    token = params.get("starting_token")
    if token is not None and (
        not isinstance(token, str) or not token or len(token) > 4096
    ):
        raise AWSPackError("starting_token is invalid")
    config: dict[str, Any] = {"MaxItems": limit}
    if token:
        config["StartingToken"] = token
    try:
        paginator = client.get_paginator(method)
        pagination_model = getattr(paginator, "_pagination_cfg", {})
        if include_page_size and (
            not pagination_model or pagination_model.get("limit_key")
        ):
            config["PageSize"] = page_size
        iterator = paginator.paginate(**kwargs, PaginationConfig=config)
        items: list[Any] = []
        pages = 0
        for page in iterator:
            pages += 1
            current = page.get(result_key, [])
            if not isinstance(current, list):
                raise AWSPackError("AWS pagination response was malformed")
            items.extend(current)
        next_token = getattr(iterator, "resume_token", None)
    except AWSPackError:
        raise
    except ClientError as exc:
        _call(_RaisingClient(exc), "request", {})
        raise AssertionError("unreachable")
    except (BotoCoreError, OSError) as exc:
        raise AWSPackError(f"AWS pagination failed: {type(exc).__name__}") from exc
    return {
        "items": items,
        "pagination": {
            "count": len(items),
            "pages": pages,
            "truncated": bool(next_token),
            "next_token": next_token,
        },
    }


class _RaisingClient:
    def __init__(self, error: Exception):
        self.error = error

    def request(self) -> None:
        raise self.error


def _confirm(params: dict[str, Any], expected: str) -> None:
    if params.get("confirm") != expected:
        raise AWSPackError("confirmation does not match the required phrase")


def _artifact_path(relative: Any, *, existing: bool) -> tuple[Path, Path]:
    root_value = os.environ.get("ATTUNE_ARTIFACTS_DIR")
    if not root_value or not os.path.isabs(root_value):
        raise AWSPackError("ATTUNE_ARTIFACTS_DIR must be an absolute directory")
    root = Path(root_value).resolve(strict=True)
    if not root.is_dir():
        raise AWSPackError("ATTUNE_ARTIFACTS_DIR must be a directory")
    if (
        not isinstance(relative, str)
        or not relative
        or os.path.isabs(relative)
        or "\x00" in relative
        or any(part in {"", ".", ".."} for part in Path(relative).parts)
    ):
        raise AWSPackError("artifact_path must be a relative path")
    candidate = root / relative
    current = root
    for part in Path(relative).parts:
        current /= part
        if current.is_symlink():
            raise AWSPackError("artifact_path must not contain symlinks")
    try:
        path = candidate.resolve(strict=existing)
        path.relative_to(root)
    except (OSError, ValueError) as exc:
        raise AWSPackError(
            "artifact_path must stay within ATTUNE_ARTIFACTS_DIR"
        ) from exc
    if existing and not path.is_file():
        raise AWSPackError("artifact_path must identify a regular artifact file")
    if not path.parent.is_dir():
        raise AWSPackError("artifact_path parent directory does not exist")
    return root, path


def _tags(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, dict) or not 1 <= len(value) <= 50:
        raise AWSPackError("tags must be an object with 1-50 entries")
    if any(
        not isinstance(key, str) or not key or not isinstance(item, str)
        for key, item in value.items()
    ):
        raise AWSPackError("tags must contain string keys and values")
    return [{"Key": key, "Value": item} for key, item in value.items()]


def _bucket(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 63
        or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", value)
        or ".." in value
    ):
        raise AWSPackError("bucket is invalid")
    try:
        ip_address(value)
    except ValueError:
        return value
    raise AWSPackError("bucket must not be an IP address")


def _template(params: dict[str, Any]) -> dict[str, Any]:
    body = params.get("template_body")
    if not isinstance(body, str) or not 1 <= len(body.encode("utf-8")) <= 51200:
        raise AWSPackError("template_body must contain 1-51200 UTF-8 bytes")
    return {"TemplateBody": body}


def _cfn_parameters(value: Any, *, allow_previous: bool = True) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, dict) or len(value) > 200:
        raise AWSPackError("parameters must be an object with at most 200 entries")
    result = []
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise AWSPackError("parameter names must be non-empty strings")
        if item is None:
            if not allow_previous:
                raise AWSPackError(
                    "null CloudFormation parameters are valid only for updates"
                )
            result.append({"ParameterKey": key, "UsePreviousValue": True})
        elif isinstance(item, (str, int, float, bool)):
            result.append(
                {
                    "ParameterKey": key,
                    "ParameterValue": str(item).lower()
                    if isinstance(item, bool)
                    else str(item),
                }
            )
        else:
            raise AWSPackError("parameter values must be scalar or null")
    return result


def _stack_request(params: dict[str, Any], *, update: bool) -> dict[str, Any]:
    name = params.get("stack_name")
    if not isinstance(name, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9-]{0,127}", name
    ):
        raise AWSPackError("stack_name is invalid")
    request = {"StackName": name, **_template(params)}
    parameters = _cfn_parameters(params.get("parameters"), allow_previous=update)
    if parameters:
        request["Parameters"] = parameters
    capabilities = params.get("capabilities", [])
    if capabilities:
        allowed = {"CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"}
        if not isinstance(capabilities, list) or not set(capabilities) <= allowed:
            raise AWSPackError("capabilities contains an unsupported value")
        request["Capabilities"] = capabilities
    if params.get("client_request_token"):
        token = params["client_request_token"]
        if not isinstance(token, str) or not re.fullmatch(
            r"[A-Za-z0-9][-A-Za-z0-9]{0,127}", token
        ):
            raise AWSPackError("client_request_token is invalid")
        request["ClientRequestToken"] = token
    if update:
        request["DisableRollback"] = False
    else:
        request["OnFailure"] = params.get("on_failure", "ROLLBACK")
    return request


def _client_request_token(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][-A-Za-z0-9]{0,127}", value
    ):
        raise AWSPackError("client_request_token is invalid")
    return value


def _execute(operation: str, params: dict[str, Any], aws: AWSContext) -> dict[str, Any]:  # noqa: C901, PLR0912, PLR0915
    read_only = operation not in _MUTATIONS

    if operation == "sts_get_caller_identity":
        response = _call(aws.client("sts"), "get_caller_identity", {})
        return _result(
            response,
            identity={
                key.lower(): response.get(key) for key in ("Account", "Arn", "UserId")
            },
        )

    if operation.startswith("ec2_"):
        client = aws.client("ec2", read_only=read_only)
        if operation == "ec2_describe_instances":
            request: dict[str, Any] = {}
            if params.get("instance_ids"):
                request["InstanceIds"] = _strings(
                    params["instance_ids"], "instance_ids", pattern=_INSTANCE_RE
                )
            if params.get("filters"):
                request["Filters"] = params["filters"]
            page = _paginate(
                client,
                "describe_instances",
                "Reservations",
                request,
                params,
                maximum=1000,
                include_page_size="InstanceIds" not in request,
                minimum_page_size=5,
            )
            page["instances"] = [
                instance
                for reservation in page.pop("items")
                for instance in reservation.get("Instances", [])
            ]
            page["pagination"]["count"] = len(page["instances"])
            return page
        if operation == "ec2_describe_images":
            request = {}
            if params.get("image_ids"):
                request["ImageIds"] = _strings(
                    params["image_ids"], "image_ids", maximum=100
                )
            if params.get("owners"):
                request["Owners"] = _strings(params["owners"], "owners", maximum=20)
            if not request:
                raise AWSPackError("image_ids or owners is required")
            page = _paginate(
                client,
                "describe_images",
                "Images",
                request,
                params,
                maximum=1000,
                include_page_size="ImageIds" not in request,
                minimum_page_size=5,
            )
            page["images"] = page.pop("items")
            return page
        ids = _strings(
            params.get("instance_ids"),
            "instance_ids",
            maximum=20 if operation == "ec2_terminate_instances" else 100,
            pattern=_INSTANCE_RE,
        )
        method = operation.removeprefix("ec2_")
        if operation in {"ec2_stop_instances", "ec2_reboot_instances"}:
            _confirm(
                params,
                f"{method.removesuffix('_instances').upper()}:{','.join(sorted(ids))}",
            )
        if operation == "ec2_terminate_instances":
            _confirm(params, f"TERMINATE:{','.join(sorted(ids))}")
        request = {"InstanceIds": ids}
        if operation in {"ec2_create_tags", "ec2_delete_tags"}:
            request = {"Resources": ids, "Tags": _tags(params.get("tags"))}
            if operation == "ec2_delete_tags":
                _confirm(params, f"DELETE-TAGS:{','.join(sorted(ids))}")
        response = _call(client, method, request)
        return _result(response, changed=True, retried=False)

    if operation.startswith("s3_"):
        client = aws.client("s3", read_only=read_only)
        if operation == "s3_list_buckets":
            page = _paginate(
                client, "list_buckets", "Buckets", {}, params, maximum=1000
            )
            page["buckets"] = page.pop("items")
            return page
        bucket, key = _bucket(params.get("bucket")), params.get("key")
        if operation == "s3_list_objects":
            request = {"Bucket": bucket}
            if params.get("prefix") is not None:
                request["Prefix"] = params["prefix"]
            return _paginate(
                client, "list_objects_v2", "Contents", request, params, maximum=10000
            )
        if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 1024:
            raise AWSPackError("key is invalid")
        if operation == "s3_head_object":
            return _result(
                _call(client, "head_object", {"Bucket": bucket, "Key": key}),
                bucket=bucket,
                key=key,
            )
        if operation == "s3_upload_object":
            _confirm(params, f"PUT:{bucket}/{key}")
            root, path = _artifact_path(params.get("artifact_path"), existing=True)
            size = path.stat().st_size
            if size > aws.profile["max_artifact_bytes"]:
                raise AWSPackError("artifact exceeds max_artifact_bytes")
            try:
                with path.open("rb") as stream:
                    response = _call(
                        client,
                        "put_object",
                        {"Bucket": bucket, "Key": key, "Body": stream},
                    )
            except OSError as exc:
                raise AWSPackError("artifact could not be read") from exc
            return _result(
                response,
                bucket=bucket,
                key=key,
                artifact_path=str(path.relative_to(root)),
                bytes=size,
                changed=True,
                retried=False,
            )
        root, path = _artifact_path(params.get("artifact_path"), existing=False)
        if path.exists() and not path.is_file():
            raise AWSPackError("artifact_path must identify a file")
        destination_existed = path.exists()
        if destination_existed:
            _confirm(params, f"OVERWRITE:{path.relative_to(root)}")
        response = _call(client, "get_object", {"Bucket": bucket, "Key": key})
        length = response.get("ContentLength")
        stream = response.get("Body")
        if stream is None:
            raise AWSPackError("AWS response did not contain an object body")
        if isinstance(length, int) and length > aws.profile["max_artifact_bytes"]:
            stream.close()
            raise AWSPackError("object exceeds max_artifact_bytes")
        written = 0
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=path.parent, prefix=".attune-s3-", delete=False
            ) as output:
                temp_name = output.name
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > aws.profile["max_artifact_bytes"]:
                        raise AWSPackError("object exceeds max_artifact_bytes")
                    output.write(chunk)
            if destination_existed:
                os.replace(temp_name, path)
            else:
                os.link(temp_name, path)
                os.unlink(temp_name)
        except OSError as exc:
            raise AWSPackError(
                "object could not be written to the artifact directory"
            ) from exc
        finally:
            stream.close()
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)
        return {
            "bucket": bucket,
            "key": key,
            "artifact_path": str(path.relative_to(root)),
            "bytes": written,
            "changed": True,
        }

    if operation.startswith("cloudformation_"):
        client = aws.client("cloudformation", read_only=read_only)
        method = operation.removeprefix("cloudformation_")
        if operation == "cloudformation_validate_template":
            return _result(
                _call(client, "validate_template", _template(params)), valid=True
            )
        if operation == "cloudformation_list_stacks":
            request = {}
            if params.get("stack_status_filters"):
                request["StackStatusFilter"] = params["stack_status_filters"]
            return _paginate(
                client, "list_stacks", "StackSummaries", request, params, maximum=1000
            )
        if operation == "cloudformation_describe_stacks":
            request = (
                {"StackName": params["stack_name"]} if params.get("stack_name") else {}
            )
            return _paginate(
                client, "describe_stacks", "Stacks", request, params, maximum=100
            )
        if operation in {"cloudformation_create_stack", "cloudformation_update_stack"}:
            update = operation.endswith("update_stack")
            request = _stack_request(params, update=update)
            if update:
                _confirm(params, f"UPDATE:{request['StackName']}")
            else:
                _confirm(params, f"CREATE:{request['StackName']}")
            return _result(_call(client, method, request), changed=True, retried=False)
        if operation == "cloudformation_delete_stack":
            name = params.get("stack_name")
            if not isinstance(name, str) or not re.fullmatch(
                r"[A-Za-z][A-Za-z0-9-]{0,127}", name
            ):
                raise AWSPackError("stack_name is invalid")
            _confirm(params, f"DELETE:{name}")
            request = {"StackName": name}
            if params.get("client_request_token"):
                request["ClientRequestToken"] = _client_request_token(
                    params["client_request_token"]
                )
            return _result(_call(client, method, request), changed=True, retried=False)
        if operation == "cloudformation_create_change_set":
            request = _stack_request(params, update=True)
            request["ChangeSetName"] = params.get("change_set_name")
            request["ChangeSetType"] = params.get("change_set_type", "UPDATE")
            if not isinstance(request["ChangeSetName"], str) or not re.fullmatch(
                r"[A-Za-z][-A-Za-z0-9]{0,127}", request["ChangeSetName"]
            ):
                raise AWSPackError("change_set_name is invalid")
            if request["ChangeSetType"] not in {"CREATE", "UPDATE"}:
                raise AWSPackError("change_set_type must be CREATE or UPDATE")
            if request["ChangeSetType"] == "CREATE" and any(
                item.get("UsePreviousValue") for item in request.get("Parameters", [])
            ):
                raise AWSPackError(
                    "null CloudFormation parameters are valid only for updates"
                )
            request.pop("DisableRollback", None)
            if "ClientRequestToken" in request:
                request["ClientToken"] = request.pop("ClientRequestToken")
            return _result(_call(client, method, request), changed=True, retried=False)
        if operation == "cloudformation_describe_change_set":
            stack = params.get("stack_name")
            change = params.get("change_set_name")
            return _paginate(
                client,
                method,
                "Changes",
                {"StackName": stack, "ChangeSetName": change},
                params,
                maximum=1000,
            )
        if operation in {
            "cloudformation_delete_change_set",
            "cloudformation_execute_change_set",
        }:
            stack = params.get("stack_name")
            change = params.get("change_set_name")
            if (
                not isinstance(stack, str)
                or not stack
                or not isinstance(change, str)
                or not change
            ):
                raise AWSPackError("stack_name and change_set_name are required")
            request = {"StackName": stack, "ChangeSetName": change}
            if operation == "cloudformation_execute_change_set" and params.get(
                "client_request_token"
            ):
                request["ClientRequestToken"] = _client_request_token(
                    params["client_request_token"]
                )
            _confirm(params, f"{method.upper()}:{stack}/{change}")
            return _result(
                _call(client, method, request),
                changed=not read_only,
                retried=False if not read_only else None,
            )
        if operation in {"cloudformation_wait_stack", "cloudformation_wait_change_set"}:
            delay = _positive(params.get("delay_seconds"), "delay_seconds", 10, 60)
            attempts = _positive(params.get("max_attempts"), "max_attempts", 60, 120)
            try:
                if operation.endswith("wait_stack"):
                    waiter_name = params.get("waiter")
                    allowed = {
                        "stack_create_complete",
                        "stack_update_complete",
                        "stack_delete_complete",
                        "stack_rollback_complete",
                    }
                    if waiter_name not in allowed:
                        raise AWSPackError("waiter is not allowed")
                    client.get_waiter(waiter_name).wait(
                        StackName=params.get("stack_name"),
                        WaiterConfig={"Delay": delay, "MaxAttempts": attempts},
                    )
                    return {
                        "complete": True,
                        "waiter": waiter_name,
                        "attempts_bound": attempts,
                    }
                terminal = {"CREATE_COMPLETE", "DELETE_COMPLETE", "FAILED"}
                last = None
                for attempt in range(1, attempts + 1):
                    last = _call(
                        client,
                        "describe_change_set",
                        {
                            "StackName": params.get("stack_name"),
                            "ChangeSetName": params.get("change_set_name"),
                        },
                    )
                    if last.get("Status") in terminal:
                        return {
                            "complete": last.get("Status") == "CREATE_COMPLETE",
                            "attempts": attempt,
                            "status": last.get("Status"),
                            "execution_status": last.get("ExecutionStatus"),
                        }
                    if attempt < attempts:
                        time.sleep(delay)
                raise AWSPackError(
                    "change set did not reach a terminal status within the polling bound"
                )
            except WaiterError as exc:
                raise AWSPackError(
                    "CloudFormation waiter reached a failure or timeout state"
                ) from exc

    if operation.startswith("route53_"):
        client = aws.client("route53", read_only=read_only)
        method = operation.removeprefix("route53_")
        if operation == "route53_list_hosted_zones":
            return _paginate(client, method, "HostedZones", {}, params, maximum=1000)
        if operation == "route53_get_change":
            change_id = params.get("change_id")
            if not isinstance(change_id, str) or not change_id:
                raise AWSPackError("change_id is required")
            return _result(_call(client, method, {"Id": change_id}))
        zone = params.get("hosted_zone_id")
        if not isinstance(zone, str) or not zone:
            raise AWSPackError("hosted_zone_id is required")
        if operation == "route53_list_resource_record_sets":
            return _paginate(
                client,
                method,
                "ResourceRecordSets",
                {"HostedZoneId": zone},
                params,
                maximum=10000,
            )
        changes = _list(params.get("changes"), "changes", maximum=1000)
        for change in changes:
            if (
                not isinstance(change, dict)
                or set(change) != {"action", "record_set"}
                or change["action"] not in {"CREATE", "DELETE", "UPSERT"}
                or not isinstance(change["record_set"], dict)
            ):
                raise AWSPackError("each change requires action and record_set")
        _confirm(params, f"CHANGE:{zone}")
        request = {
            "HostedZoneId": zone,
            "ChangeBatch": {
                "Changes": [
                    {"Action": item["action"], "ResourceRecordSet": item["record_set"]}
                    for item in changes
                ]
            },
        }
        if params.get("comment"):
            request["ChangeBatch"]["Comment"] = params["comment"]
        return _result(_call(client, method, request), changed=True, retried=False)

    if operation.startswith("rds_"):
        client = aws.client("rds", read_only=read_only)
        method = operation.removeprefix("rds_")
        if operation in {"rds_describe_instances", "rds_describe_clusters"}:
            cluster = operation.endswith("clusters")
            key = "DBClusters" if cluster else "DBInstances"
            request = {}
            identifier = params.get(
                "db_cluster_identifier" if cluster else "db_instance_identifier"
            )
            if identifier:
                request[
                    "DBClusterIdentifier" if cluster else "DBInstanceIdentifier"
                ] = identifier
            return _paginate(
                client,
                "describe_db_clusters" if cluster else "describe_db_instances",
                key,
                request,
                params,
                maximum=1000,
                minimum_page_size=20,
            )
        cluster = operation.endswith("cluster")
        field = "db_cluster_identifier" if cluster else "db_instance_identifier"
        target = params.get(field)
        if not isinstance(target, str) or not target:
            raise AWSPackError(f"{field} is required")
        if "stop_" in operation:
            _confirm(params, f"STOP:{target}")
        request = {"DBClusterIdentifier" if cluster else "DBInstanceIdentifier": target}
        return _result(
            _call(
                client,
                method.replace("_instance", "_db_instance").replace(
                    "_cluster", "_db_cluster"
                ),
                request,
            ),
            changed=True,
            retried=False,
        )

    if operation.startswith("autoscaling_"):
        client = aws.client("autoscaling", read_only=read_only)
        if operation == "autoscaling_describe_groups":
            request = {}
            if params.get("group_names"):
                request["AutoScalingGroupNames"] = _strings(
                    params["group_names"], "group_names", maximum=50
                )
            return _paginate(
                client,
                "describe_auto_scaling_groups",
                "AutoScalingGroups",
                request,
                params,
                maximum=1000,
            )
        name, desired = params.get("group_name"), params.get("desired_capacity")
        if (
            not isinstance(name, str)
            or not name
            or isinstance(desired, bool)
            or not isinstance(desired, int)
            or desired < 0
        ):
            raise AWSPackError(
                "group_name and a non-negative desired_capacity are required"
            )
        _confirm(params, f"SET:{name}:{desired}")
        return _result(
            _call(
                client,
                "set_desired_capacity",
                {
                    "AutoScalingGroupName": name,
                    "DesiredCapacity": desired,
                    "HonorCooldown": bool(params.get("honor_cooldown", True)),
                },
            ),
            changed=True,
            retried=False,
        )

    if operation.startswith("lambda_"):
        client = aws.client("lambda", read_only=read_only)
        if operation == "lambda_list_functions":
            return _paginate(
                client, "list_functions", "Functions", {}, params, maximum=1000
            )
        function = params.get("function_name")
        if not isinstance(function, str) or not function:
            raise AWSPackError("function_name is required")
        if operation == "lambda_get_function":
            return _result(
                _call(client, "get_function", {"FunctionName": function}),
                function_name=function,
            )
        _confirm(params, f"INVOKE:{function}")
        invocation_type = params.get("invocation_type", "RequestResponse")
        if invocation_type not in {"Event", "RequestResponse", "DryRun"}:
            raise AWSPackError("invocation_type is invalid")
        payload = json.dumps(params.get("payload", {}), separators=(",", ":")).encode(
            "utf-8"
        )
        if len(payload) > 1048576:
            raise AWSPackError("payload exceeds the pack's 1 MiB limit")
        response = _call(
            client,
            "invoke",
            {
                "FunctionName": function,
                "InvocationType": invocation_type,
                "Payload": payload,
            },
        )
        stream = response.pop("Payload", None)
        if stream is not None:
            body = stream.read(1048577)
            stream.close()
            if len(body) > 1048576:
                raise AWSPackError("Lambda response exceeds the pack's 1 MiB limit")
            try:
                response["Payload"] = json.loads(body) if body else None
            except (json.JSONDecodeError, UnicodeDecodeError):
                response["Payload"] = {
                    "encoding": "base64",
                    "data": base64.b64encode(body).decode("ascii"),
                }
        return _result(response, invoked=True, retried=False)

    if operation.startswith("iam_"):
        client = aws.client("iam")
        method = operation.removeprefix("iam_")
        lists = {
            "iam_list_users": ("list_users", "Users"),
            "iam_list_roles": ("list_roles", "Roles"),
            "iam_list_policies": ("list_policies", "Policies"),
            "iam_list_groups": ("list_groups", "Groups"),
        }
        if operation in lists:
            method, key = lists[operation]
            request = (
                {"Scope": params.get("scope", "Local")}
                if operation == "iam_list_policies"
                else {}
            )
            return _paginate(client, method, key, request, params, maximum=1000)
        field = "UserName" if operation == "iam_get_user" else "RoleName"
        name = params.get("user_name" if operation == "iam_get_user" else "role_name")
        return _result(_call(client, method, {field: name}), read_only=True)

    raise AWSPackError("unknown or unsupported AWS action")


def execute_with_context(
    operation: str, params: dict[str, Any], context: AWSContext
) -> dict[str, Any]:
    result = _execute(operation, params, context)
    secrets = tuple(
        value
        for key, value in context.profile.items()
        if isinstance(value, str) and key in _PROFILE_SECRET_KEYS
    )
    return _safe(result, secrets)


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    credential_key = params.get("credential_key", "aws.credentials")
    profile = _fetch_key(credential_key)
    context = AWSContext(profile, params.get("region"))
    return execute_with_context(operation, params, context)
