"""Read/write the deployment manifest (manifest.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import TypedDict

import yaml

MANIFEST_FILE = Path.home() / ".config" / "sshkey-ui" / "manifest.yaml"


class Deployment(TypedDict):
    alias: str
    user: str


def load() -> list[Deployment]:
    if not MANIFEST_FILE.exists():
        return []
    try:
        data = yaml.safe_load(MANIFEST_FILE.read_text()) or {}
        return data.get("deployments", [])
    except Exception:
        return []


def save(entries: list[Deployment]) -> None:
    MANIFEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_FILE.write_text(yaml.dump({"deployments": entries}, default_flow_style=False))
    MANIFEST_FILE.chmod(0o600)
