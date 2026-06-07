"""Live SSH deployment check and manifest status."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

from sshkey_ui.bitwarden import SSHKeyItem
from sshkey_ui.manifest import Deployment

BW_PUB_DIR = Path.home() / ".ssh" / "bwpub"

# Possible status values
STATUS_CONFIRMED   = "confirmed"
STATUS_MISSING     = "missing"
STATUS_UNREACHABLE = "unreachable"
STATUS_AUTH_FAILED = "auth_failed"
STATUS_UNKNOWN     = "unknown"


def manifest_status(item: SSHKeyItem, deployments: list[Deployment]) -> str:
    """Return status based solely on the manifest (no network call)."""
    declared = any(
        d.get("alias") == item.alias and d.get("user", "") == item.user
        for d in deployments
    )
    return STATUS_UNKNOWN if not declared else STATUS_UNKNOWN


async def live_check(item: SSHKeyItem) -> tuple[str, list[str]]:
    """SSH into the server and check whether our public key is in authorized_keys.

    Returns (status, log_lines).
    """
    log: list[str] = []

    if not item.hostname or not item.alias:
        log.append(f"[SKIP] {item.alias or item.id} — no hostname set")
        return STATUS_UNKNOWN, log

    pub_path = BW_PUB_DIR / item.pub_filename
    if not pub_path.exists():
        log.append(f"[SKIP] {item.host_alias} — pub file missing, run Sync first")
        return STATUS_UNKNOWN, log

    pubkey_content = pub_path.read_text().strip()

    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=8",
        "-o", "PasswordAuthentication=no",
        item.host_alias,
        "cat ~/.ssh/authorized_keys 2>/dev/null || true",
    ]
    log.append(f"[CHECK] {item.host_alias} ({item.hostname}:{item.port or 22})")
    log.append(f"[CMD]   {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=12)
        auth_keys = stdout.decode(errors="replace")
        stderr_text = stderr.decode(errors="replace").strip()

        if stderr_text:
            log.append(f"[STDERR] {stderr_text}")

        # strip comment from pubkey for comparison (type + key material only)
        pub_parts = pubkey_content.split()
        pub_material = " ".join(pub_parts[:2]) if len(pub_parts) >= 2 else pubkey_content

        if any(pub_material in line for line in auth_keys.splitlines()):
            log.append(f"[OK] key found in authorized_keys")
            return STATUS_CONFIRMED, log
        if proc.returncode == 0:
            log.append(f"[MISSING] connected ok but key not in authorized_keys")
            return STATUS_MISSING, log
        if any(s in stderr_text for s in ("Permission denied", "publickey", "No more authentication")):
            log.append(f"[AUTH FAILED] check BW agent or local key for {item.host_alias}")
            return STATUS_AUTH_FAILED, log
        log.append(f"[UNREACHABLE] exit {proc.returncode}")
        return STATUS_UNREACHABLE, log
    except asyncio.TimeoutError:
        log.append(f"[TIMEOUT] no response after 12s")
        return STATUS_UNREACHABLE, log
    except OSError as e:
        log.append(f"[ERROR] {e}")
        return STATUS_UNREACHABLE, log
