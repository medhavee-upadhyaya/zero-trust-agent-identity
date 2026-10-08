from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .model import canonical_bytes


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class SignedEnvelope:
    kind: str
    signer_id: str
    payload: Any
    signature: str

    def signing_bytes(self) -> bytes:
        return canonical_bytes({"kind": self.kind, "payload": self.payload, "signer_id": self.signer_id})


class Ed25519Signer:
    def __init__(self, signer_id: str, private_key: Ed25519PrivateKey | None = None) -> None:
        self.signer_id = signer_id
        self._private_key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def public_key_fingerprint(self) -> str:
        return hashlib.sha256(self.public_key_bytes).hexdigest()

    @property
    def private_key_bytes(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @classmethod
    def from_private_bytes(cls, signer_id: str, private_key: bytes) -> "Ed25519Signer":
        return cls(signer_id, Ed25519PrivateKey.from_private_bytes(private_key))

    def sign(self, kind: str, payload: Any) -> SignedEnvelope:
        unsigned = SignedEnvelope(kind=kind, signer_id=self.signer_id, payload=payload, signature="")
        return SignedEnvelope(
            kind=kind,
            signer_id=self.signer_id,
            payload=payload,
            signature=_b64(self._private_key.sign(unsigned.signing_bytes())),
        )


class TrustStore:
    def __init__(self) -> None:
        self._keys: dict[tuple[str, str], Ed25519PublicKey] = {}

    def register(self, role: str, signer: Ed25519Signer) -> None:
        self.register_public_key(role, signer.signer_id, signer.public_key_bytes)

    def register_public_key(self, role: str, signer_id: str, public_key: bytes) -> None:
        self._keys[(role, signer_id)] = Ed25519PublicKey.from_public_bytes(public_key)

    def verify(self, role: str, envelope: SignedEnvelope, expected_kind: str) -> bool:
        if envelope.kind != expected_kind:
            return False
        key = self._keys.get((role, envelope.signer_id))
        if key is None:
            return False
        try:
            key.verify(_unb64(envelope.signature), envelope.signing_bytes())
        except (InvalidSignature, ValueError):
            return False
        return True

    def public_key_fingerprint(self, role: str, signer_id: str) -> str | None:
        key = self._keys.get((role, signer_id))
        if key is None:
            return None
        raw = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha256(raw).hexdigest()
