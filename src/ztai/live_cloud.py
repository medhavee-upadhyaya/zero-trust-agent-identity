from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Mapping, Protocol

from .cloud_identity import (
    GoogleWorkloadFederationConfig,
    MicrosoftEntraFederationConfig,
)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
    ) -> HttpResponse: ...


class UrllibTransport:
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
    ) -> HttpResponse:
        request = urllib.request.Request(
            url,
            method=method,
            headers=dict(headers),
            data=body,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return HttpResponse(
                    int(response.status),
                    dict(response.headers.items()),
                    response.read(),
                )
        except urllib.error.HTTPError as error:
            return HttpResponse(
                int(error.code),
                dict(error.headers.items()),
                error.read(),
            )


@dataclass(frozen=True)
class CloudAccessToken:
    provider: str
    token_type: str
    expires_in: int
    access_token: str = field(repr=False)


@dataclass(frozen=True)
class LiveCloudEffectResult:
    provider: str
    resource: str
    status: int
    committed: bool
    payload_sha256: str
    response_request_id: str
    error_code: str = ""


def _json_object(response: HttpResponse) -> dict[str, object]:
    try:
        value = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cloud endpoint returned non-JSON status {response.status}") from error
    if not isinstance(value, dict):
        raise RuntimeError("cloud endpoint returned a non-object JSON response")
    return value


def _access_token(provider: str, response: HttpResponse) -> CloudAccessToken:
    payload = _json_object(response)
    if not 200 <= response.status < 300:
        code = str(payload.get("error", payload.get("error_description", "token_exchange_failed")))
        raise RuntimeError(f"{provider} token exchange failed: {code}")
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError(f"{provider} token response omitted access_token")
    try:
        expires_in = int(payload.get("expires_in", 0))
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"{provider} token response has invalid expires_in") from error
    if expires_in <= 0:
        raise RuntimeError(f"{provider} token response has non-positive expires_in")
    return CloudAccessToken(
        provider,
        str(payload.get("token_type", "Bearer")),
        expires_in,
        token,
    )


class GoogleFederationClient:
    def __init__(self, transport: HttpTransport, *, timeout: float = 10.0) -> None:
        self._transport = transport
        self._timeout = timeout

    def exchange(
        self,
        config: GoogleWorkloadFederationConfig,
        jwt_svid: str,
    ) -> CloudAccessToken:
        request = config.token_exchange(jwt_svid)
        response = self._transport.request(
            "POST",
            request.token_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=request.encoded_body(),
            timeout=self._timeout,
        )
        return _access_token("google", response)


class MicrosoftFederationClient:
    def __init__(self, transport: HttpTransport, *, timeout: float = 10.0) -> None:
        self._transport = transport
        self._timeout = timeout

    def exchange(
        self,
        config: MicrosoftEntraFederationConfig,
        jwt_svid: str,
    ) -> CloudAccessToken:
        body = urllib.parse.urlencode(config.client_assertion_fields(jwt_svid)).encode("ascii")
        response = self._transport.request(
            "POST",
            config.token_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
            timeout=self._timeout,
        )
        return _access_token("microsoft", response)


class GoogleCloudStorageAdapter:
    def __init__(self, transport: HttpTransport, *, timeout: float = 10.0) -> None:
        self._transport = transport
        self._timeout = timeout

    def put_object(
        self,
        *,
        token: CloudAccessToken,
        bucket: str,
        object_name: str,
        payload: bytes,
        allow_live_effect: bool,
    ) -> LiveCloudEffectResult:
        if not allow_live_effect:
            raise PermissionError("live cloud writes require explicit confirmation")
        if token.provider != "google":
            raise ValueError("Google Cloud Storage requires a Google access token")
        resource = f"gs://{bucket}/{object_name}"
        query = urllib.parse.urlencode({"uploadType": "media", "name": object_name})
        escaped_bucket = urllib.parse.quote(bucket, safe="")
        url = (
            "https://storage.googleapis.com/upload/storage/v1/b/"
            f"{escaped_bucket}/o?{query}"
        )
        response = self._transport.request(
            "POST",
            url,
            headers={
                "Authorization": f"{token.token_type} {token.access_token}",
                "Content-Type": "application/octet-stream",
            },
            body=payload,
            timeout=self._timeout,
        )
        body = _json_object(response)
        request_id = str(response.headers.get("x-guploader-uploadid", ""))
        error_code = "" if response.status < 300 else str(body.get("error", "cloud_write_failed"))
        return LiveCloudEffectResult(
            "google",
            resource,
            response.status,
            200 <= response.status < 300,
            hashlib.sha256(payload).hexdigest(),
            request_id,
            error_code,
        )


class AzureBlobStorageAdapter:
    def __init__(self, transport: HttpTransport, *, timeout: float = 10.0) -> None:
        self._transport = transport
        self._timeout = timeout

    def put_blob(
        self,
        *,
        token: CloudAccessToken,
        account: str,
        container: str,
        blob_name: str,
        payload: bytes,
        allow_live_effect: bool,
    ) -> LiveCloudEffectResult:
        if not allow_live_effect:
            raise PermissionError("live cloud writes require explicit confirmation")
        if token.provider != "microsoft":
            raise ValueError("Azure Blob Storage requires a Microsoft access token")
        resource = f"https://{account}.blob.core.windows.net/{container}/{blob_name}"
        response = self._transport.request(
            "PUT",
            resource,
            headers={
                "Authorization": f"{token.token_type} {token.access_token}",
                "Content-Type": "application/octet-stream",
                "x-ms-blob-type": "BlockBlob",
                "x-ms-version": "2023-11-03",
            },
            body=payload,
            timeout=self._timeout,
        )
        request_id = str(response.headers.get("x-ms-request-id", ""))
        error_code = "" if response.status < 300 else str(response.status)
        return LiveCloudEffectResult(
            "microsoft",
            resource,
            response.status,
            200 <= response.status < 300,
            hashlib.sha256(payload).hexdigest(),
            request_id,
            error_code,
        )
