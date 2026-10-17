from __future__ import annotations

import json
import unittest

from ztai import (
    AzureBlobStorageAdapter,
    CloudAccessToken,
    GoogleCloudStorageAdapter,
    GoogleFederationClient,
    GoogleWorkloadFederationConfig,
    HttpResponse,
    MicrosoftEntraFederationConfig,
    MicrosoftFederationClient,
)


class RecordingTransport:
    def __init__(self, responses: list[HttpResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []

    def request(self, method, url, *, headers, body, timeout):
        self.requests.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        return self.responses.pop(0)


def token_response() -> HttpResponse:
    return HttpResponse(
        200,
        {},
        json.dumps(
            {
                "access_token": "cloud-secret-token",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        ).encode(),
    )


class LiveCloudTests(unittest.TestCase):
    def test_google_token_exchange_and_object_write(self) -> None:
        transport = RecordingTransport(
            [
                token_response(),
                HttpResponse(
                    200,
                    {"x-guploader-uploadid": "request-google-7"},
                    b'{"name":"case-7.json"}',
                ),
            ]
        )
        token = GoogleFederationClient(transport).exchange(
            GoogleWorkloadFederationConfig("123456", "agents", "spire"),
            "jwt-svid-secret",
        )
        self.assertNotIn("cloud-secret-token", repr(token))
        result = GoogleCloudStorageAdapter(transport).put_object(
            token=token,
            bucket="ztai-test",
            object_name="case-7.json",
            payload=b'{"case":"7"}',
            allow_live_effect=True,
        )
        self.assertTrue(result.committed)
        self.assertEqual(result.response_request_id, "request-google-7")
        self.assertIn("jwt-svid-secret", transport.requests[0]["body"].decode())
        self.assertEqual(
            transport.requests[1]["headers"]["Authorization"],
            "Bearer cloud-secret-token",
        )
        self.assertNotIn("cloud-secret-token", repr(result))

    def test_microsoft_token_exchange_and_blob_write(self) -> None:
        transport = RecordingTransport(
            [
                token_response(),
                HttpResponse(201, {"x-ms-request-id": "request-azure-7"}, b""),
            ]
        )
        token = MicrosoftFederationClient(transport).exchange(
            MicrosoftEntraFederationConfig(
                "tenant-7", "client-7", "https://storage.azure.com/.default"
            ),
            "jwt-svid-secret",
        )
        result = AzureBlobStorageAdapter(transport).put_blob(
            token=token,
            account="ztaitest",
            container="evidence",
            blob_name="case-7.json",
            payload=b'{"case":"7"}',
            allow_live_effect=True,
        )
        self.assertTrue(result.committed)
        self.assertEqual(result.status, 201)
        self.assertEqual(result.response_request_id, "request-azure-7")
        self.assertEqual(transport.requests[1]["headers"]["x-ms-blob-type"], "BlockBlob")

    def test_live_effects_require_explicit_confirmation(self) -> None:
        transport = RecordingTransport([])
        google_token = CloudAccessToken("google", "Bearer", 3600, "secret")
        with self.assertRaises(PermissionError):
            GoogleCloudStorageAdapter(transport).put_object(
                token=google_token,
                bucket="bucket",
                object_name="object",
                payload=b"payload",
                allow_live_effect=False,
            )
        microsoft_token = CloudAccessToken("microsoft", "Bearer", 3600, "secret")
        with self.assertRaises(PermissionError):
            AzureBlobStorageAdapter(transport).put_blob(
                token=microsoft_token,
                account="account",
                container="container",
                blob_name="blob",
                payload=b"payload",
                allow_live_effect=False,
            )
        self.assertEqual(transport.requests, [])

    def test_error_response_never_exposes_access_token(self) -> None:
        transport = RecordingTransport(
            [HttpResponse(400, {}, b'{"error":"invalid_target"}')]
        )
        with self.assertRaisesRegex(RuntimeError, "invalid_target") as context:
            GoogleFederationClient(transport).exchange(
                GoogleWorkloadFederationConfig("123456", "agents", "spire"),
                "jwt-svid-secret",
            )
        self.assertNotIn("jwt-svid-secret", str(context.exception))


if __name__ == "__main__":
    unittest.main()
