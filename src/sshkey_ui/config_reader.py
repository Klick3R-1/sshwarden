"""Parse bwpub.auto.conf and bwpub-local.conf into structured stanzas."""

from __future__ import annotations

from pathlib import Path

AUTO_CONF  = Path.home() / ".ssh" / "config.d" / "bwpub.auto.conf"
LOCAL_CONF = Path.home() / ".ssh" / "config.d" / "bwpub-local.conf"


def _parse(path: Path) -> dict[str, dict[str, str]]:
    """Return {host_alias: {Directive: value}} preserving insertion order."""
    stanzas: dict[str, dict[str, str]] = {}
    current: str | None = None
    if not path.exists():
        return stanzas
    for line in path.read_text().splitlines():
        line = line.replace("\r", "")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lower().startswith("host "):
            current = stripped[5:].strip()
            stanzas.setdefault(current, {})
        elif current is not None:
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                stanzas[current][parts[0]] = parts[1]
    return stanzas


def load() -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """Return (auto_stanzas, local_stanzas)."""
    return _parse(AUTO_CONF), _parse(LOCAL_CONF)
