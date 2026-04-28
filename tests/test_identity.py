"""Tests for agno_dcp.identity."""

from __future__ import annotations

import json

import pytest

from agno_dcp import (
    CitizenshipBundle,
    IdentityError,
    deserialize_bundle,
    generate_citizenship_bundle,
    load_citizenship_bundle,
    serialize_bundle,
    verify_citizenship_bundle,
)
from agno_dcp.storage.sqlite import SQLiteStorage


def test_generate_citizenship_bundle_basic() -> None:
    bundle, secret = generate_citizenship_bundle(
        agent_name="Test Agent",
        human_principal="ops@example.com",
    )
    assert isinstance(bundle, CitizenshipBundle)
    assert bundle.agent_id.startswith("agent:")
    assert bundle.bundle_id.startswith("bundle:")
    assert bundle.agent_name == "Test Agent"
    assert bundle.human_principal == "ops@example.com"
    assert bundle.security_tier == "tier-2"
    assert bundle.public_key_b64
    assert bundle.signature_b64
    assert isinstance(secret, str) and len(secret) > 0
    assert verify_citizenship_bundle(bundle) is True


def test_generate_citizenship_bundle_with_metadata() -> None:
    bundle, _ = generate_citizenship_bundle(
        agent_name="With meta",
        human_principal="x@example.com",
        security_tier="tier-3",
        metadata={"team": "collections", "env": "prod"},
    )
    assert bundle.security_tier == "tier-3"
    assert bundle.metadata == {"team": "collections", "env": "prod"}
    assert verify_citizenship_bundle(bundle) is True


def test_generate_rejects_empty_inputs() -> None:
    with pytest.raises(IdentityError):
        generate_citizenship_bundle(agent_name="", human_principal="x")
    with pytest.raises(IdentityError):
        generate_citizenship_bundle(agent_name="x", human_principal="")
    with pytest.raises(IdentityError):
        generate_citizenship_bundle(agent_name="   ", human_principal="x")


def test_verify_detects_tampering() -> None:
    bundle, _ = generate_citizenship_bundle(agent_name="Tamper", human_principal="x@example.com")
    assert verify_citizenship_bundle(bundle) is True
    bundle.agent_name = "Mutated"
    assert verify_citizenship_bundle(bundle) is False


def test_verify_returns_false_when_signature_missing() -> None:
    bundle, _ = generate_citizenship_bundle(agent_name="A", human_principal="x@example.com")
    bundle.signature_b64 = ""
    assert verify_citizenship_bundle(bundle) is False


def test_serialize_roundtrip() -> None:
    bundle, _ = generate_citizenship_bundle(
        agent_name="Round Trip", human_principal="x@example.com"
    )
    serialized = serialize_bundle(bundle)
    parsed_back = deserialize_bundle(serialized)
    assert parsed_back.model_dump() == bundle.model_dump()
    assert verify_citizenship_bundle(parsed_back) is True

    # also accepts dict input
    parsed_back2 = deserialize_bundle(json.loads(serialized))
    assert parsed_back2.agent_id == bundle.agent_id


def test_deserialize_rejects_bad_json() -> None:
    with pytest.raises(IdentityError):
        deserialize_bundle("not json")
    with pytest.raises(IdentityError):
        deserialize_bundle({"missing": "fields"})


@pytest.mark.asyncio
async def test_load_from_storage_roundtrip(storage: SQLiteStorage) -> None:
    bundle, _ = generate_citizenship_bundle(agent_name="Loader", human_principal="x@example.com")
    await storage.put_citizenship_bundle(bundle.model_dump())
    loaded = await load_citizenship_bundle(bundle.agent_id, storage)
    assert loaded.agent_id == bundle.agent_id
    assert loaded.signature_b64 == bundle.signature_b64


@pytest.mark.asyncio
async def test_load_missing_raises(storage: SQLiteStorage) -> None:
    with pytest.raises(IdentityError):
        await load_citizenship_bundle("agent:does-not-exist", storage)


@pytest.mark.asyncio
async def test_load_tampered_raises(storage: SQLiteStorage) -> None:
    bundle, _ = generate_citizenship_bundle(
        agent_name="Tampered Loader", human_principal="x@example.com"
    )
    raw = bundle.model_dump()
    raw["agent_name"] = "Mutated"
    await storage.put_citizenship_bundle(raw)
    with pytest.raises(IdentityError):
        await load_citizenship_bundle(bundle.agent_id, storage)
