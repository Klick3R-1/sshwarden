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
STATUS_UNKNOWN     = "unknown"


def manifest_status(item: SSHKeyItem, deployments: list[Deployment]) -> str:
    """Return status based solely on the manifest (no network call)."""
    declared = any(
        d.get("alias") == item.alias and d.get("user", "") == item.user
        for d in deployments
    )
    return STATUS_UNKNOWN if not declared else STATUS_UNKNOWN


async def live_check(item: SSHKeyItem) -> str:
    """SSH into the server and check whether our public key is in authorized_keys."""
    if not item.hostname or not item.alias:
        return STATUS_UNKNOWN

    pub_path = BW_PUB_DIR / item.pub_filename
    if not pub_path.exists():
        return STATUS_UNKNOWN

    pubkey_content = pub_path.read_text().strip()

    user_host = f"{item.user}@{item.hostname}" if item.user else item.hostname
    port = item.port or "22"

    cmd = [
        "ssh",
        "-p", port,
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=8",
        "-o", "PasswordAuthentication=no",
        user_host,
        "cat ~/.ssh/authorized_keys 2>/dev/null || true",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=12)
        auth_keys = stdout.decode(errors="replace")

        # strip comment from pubkey for comparison (type + key material only)
        pub_parts = pubkey_content.split()
        pub_material = " ".join(pub_parts[:2]) if len(pub_parts) >= 2 else pubkey_content

        if any(pub_material in line for line in auth_keys.splitlines()):
            return STATUS_CONFIRMED
        if proc.returncode == 0:
            return STATUS_MISSING
        return STATUS_UNREACHABLE
    except (asyncio.TimeoutError, OSError):
        return STATUS_UNREACHABLE
