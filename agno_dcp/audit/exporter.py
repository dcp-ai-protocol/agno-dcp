"""Compliance Bundle exporter.

Produces a signed ZIP archive containing everything an external
auditor needs to verify a slice of the system's behaviour without
talking to the live deployment:

* ``manifest.json``: bundle metadata (framework, ranges, signatures).
* ``citizenship_bundles/``: every relevant agent identity record.
* ``audit_log.jsonl``: the audit chain entries in index order.
* ``roots.jsonl``: every sealed Merkle root snapshot.
* ``compliance_mapping.json``: which DCP-AI capabilities cover which
  control in the chosen framework (EU AI Act or NIST AI RMF).

The whole archive is signed with the audit chain's keypair so the
auditor can detect tampering between export and review.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from agno_dcp.audit.chain import MerkleAuditChain
from agno_dcp.compliance.eu_ai_act import EU_AI_ACT_MAPPING
from agno_dcp.compliance.nist_ai_rmf import NIST_AI_RMF_MAPPING
from agno_dcp.exceptions import IdentityError
from agno_dcp.storage.base import BaseStorage

logger = logging.getLogger(__name__)


Framework = Literal["eu_ai_act", "nist_ai_rmf"]


def _import_dcp_primitives() -> tuple[Any, Any]:
    try:
        from dcp_ai.crypto import sign_object
        from dcp_ai.merkle import hash_object
    except ImportError as exc:  # pragma: no cover
        raise IdentityError(
            "dcp_ai SDK is required for compliance export. "
            "Install it with: pip install dcp-ai>=2.8.1"
        ) from exc
    return sign_object, hash_object


class ComplianceBundleManifest(BaseModel):
    """Top-level manifest written into the exported ZIP."""

    bundle_format_version: str
    exported_at: str
    framework: Framework
    agent_filter: str | None
    range_start: int
    range_end: int | None
    entries_count: int
    roots_count: int
    bundles_count: int
    archive_sha256: str
    signature_b64: str
    signer_public_key_b64: str


class ComplianceBundleExporter:
    """Produces signed ZIP compliance bundles.

    Args:
        audit_chain: Source of audit entries and roots.
        storage: Optional explicit storage. Defaults to
            ``audit_chain.storage``.
    """

    BUNDLE_FORMAT_VERSION = "1.0"

    def __init__(
        self,
        audit_chain: MerkleAuditChain,
        storage: BaseStorage | None = None,
    ) -> None:
        self.audit_chain = audit_chain
        self.storage = storage or audit_chain.storage

    async def export(
        self,
        framework: Framework,
        output_dir: Path,
        *,
        agent_id: str | None = None,
        range_start: int = 0,
        range_end: int | None = None,
        bundle_name: str | None = None,
    ) -> Path:
        """Build, sign, and persist a Compliance Bundle.

        Args:
            framework: Compliance framework whose mapping to embed.
            output_dir: Directory where the ZIP is written. Created
                if it does not exist.
            agent_id: If set, only this agent's slice is exported.
            range_start: Lower bound (inclusive) for entry indices.
            range_end: Upper bound (exclusive). ``None`` means up to
                the latest entry.
            bundle_name: Override the file stem. Defaults to
                ``compliance_<framework>_<timestamp>``.

        Returns:
            Path to the written ``.zip`` file.
        """
        sign_object, hash_object = _import_dcp_primitives()
        output_dir.mkdir(parents=True, exist_ok=True)

        entries = await self.storage.get_audit_entries(
            agent_id=agent_id, start=range_start, end=range_end
        )
        latest_root = await self.storage.get_latest_audit_root(agent_id=agent_id)
        roots = [latest_root] if latest_root is not None else []

        bundles: list[dict[str, Any]] = []
        seen_agents: set[str] = set()
        if agent_id is not None:
            seen_agents.add(agent_id)
        for e in entries:
            aid = e.get("agent_id")
            if aid:
                seen_agents.add(aid)
        for aid in sorted(seen_agents):
            b = await self.storage.get_citizenship_bundle(aid)
            if b is not None:
                bundles.append(b)

        mapping = EU_AI_ACT_MAPPING if framework == "eu_ai_act" else NIST_AI_RMF_MAPPING

        # Build the in-memory ZIP first so we can hash and sign it.
        buf = io.BytesIO()
        exported_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        manifest_seed = {
            "bundle_format_version": self.BUNDLE_FORMAT_VERSION,
            "exported_at": exported_at,
            "framework": framework,
            "agent_filter": agent_id,
            "range_start": range_start,
            "range_end": range_end,
            "entries_count": len(entries),
            "roots_count": len(roots),
            "bundles_count": len(bundles),
        }

        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "manifest_seed.json",
                json.dumps(manifest_seed, sort_keys=True, indent=2),
            )
            zf.writestr(
                "compliance_mapping.json",
                json.dumps(mapping, sort_keys=True, indent=2),
            )
            zf.writestr(
                "audit_log.jsonl",
                "\n".join(json.dumps(e, sort_keys=True, default=str) for e in entries),
            )
            zf.writestr(
                "roots.jsonl",
                "\n".join(json.dumps(r, sort_keys=True, default=str) for r in roots),
            )
            for b in bundles:
                aid = b.get("agent_id", "unknown")
                zf.writestr(
                    f"citizenship_bundles/{aid}.json",
                    json.dumps(b, sort_keys=True, indent=2),
                )

        archive_bytes = buf.getvalue()
        archive_sha256 = hash_object({"_archive_bytes": archive_bytes.hex()})

        manifest_full = {
            **manifest_seed,
            "archive_sha256": archive_sha256,
            "signer_public_key_b64": self.audit_chain.signer_public_key_b64,
        }
        signature = sign_object(manifest_full, self.audit_chain._signer_secret_b64)
        manifest_full["signature_b64"] = signature

        # Re-open the zip in append mode and add the final manifest.
        # We work on a fresh zip in-memory rather than the BytesIO so
        # the on-disk artifact is always single-pass written.
        final_buf = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as src:
            with zipfile.ZipFile(final_buf, "w", compression=zipfile.ZIP_DEFLATED) as dst:
                for item in src.namelist():
                    if item == "manifest_seed.json":
                        continue
                    dst.writestr(item, src.read(item))
                dst.writestr(
                    "manifest.json",
                    json.dumps(manifest_full, sort_keys=True, indent=2),
                )

        if bundle_name is None:
            stamp = exported_at.replace(":", "").replace("-", "").replace(".", "")
            bundle_name = f"compliance_{framework}_{stamp}"
        out_path = output_dir / f"{bundle_name}.zip"
        out_path.write_bytes(final_buf.getvalue())
        logger.info(
            "Wrote compliance bundle: framework=%s entries=%d path=%s",
            framework,
            len(entries),
            out_path,
        )
        return out_path


__all__ = ["ComplianceBundleExporter", "ComplianceBundleManifest"]
