"""Manage local SSH keys stored in ~/.ssh/local/ (not in Bitwarden)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sshkey_ui.config_reader import LOCAL_CONF

LOCAL_KEY_DIR = Path.home() / ".ssh" / "local"


@dataclass
class LocalKey:
    stem: str          # filename stem, e.g. myserver__root
    alias: str
    user: str
    fingerprint: str
    key_type: str
    pub_content: str
    age_days: int
    in_local_conf: bool

    @property
    def host_alias(self) -> str:
        return f"{self.alias}::{self.user}" if self.user else self.alias

    @property
    def priv_path(self) -> Path:
        return LOCAL_KEY_DIR / self.stem

    @property
    def pub_path(self) -> Path:
        return LOCAL_KEY_DIR / f"{self.stem}.pub"

    @property
    def age_label(self) -> str:
        if self.age_days < 30:
            return f"{self.age_days}d"
        if self.age_days < 365:
            return f"{self.age_days // 30}mo"
        years, rem = divmod(self.age_days, 365)
        months = rem // 30
        return f"{years}y {months}mo" if months else f"{years}y"

    @property
    def age_color(self) -> str:
        if self.age_days < 180:  return "ok"
        if self.age_days < 365:  return "warn"
        return "danger"


def _local_conf_key_paths() -> set[str]:
    """Return the set of IdentityFile paths referenced in bwpub.local.conf."""
    paths: set[str] = set()
    if not LOCAL_CONF.exists():
        return paths
    for line in LOCAL_CONF.read_text().splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("identityfile "):
            paths.add(stripped.split(None, 1)[1].strip())
    return paths


def list_local_keys() -> list[LocalKey]:
    LOCAL_KEY_DIR.mkdir(parents=True, exist_ok=True)
    LOCAL_KEY_DIR.chmod(0o700)

    conf_paths = _local_conf_key_paths()
    keys: list[LocalKey] = []

    for pub_path in sorted(LOCAL_KEY_DIR.glob("*.pub")):
        priv_path = pub_path.with_suffix("")
        if not priv_path.exists():
            continue

        pub_content = pub_path.read_text().strip()

        fp_result = subprocess.run(
            ["ssh-keygen", "-l", "-E", "sha256", "-f", str(pub_path)],
            capture_output=True, text=True,
        )
        parts = fp_result.stdout.split() if fp_result.returncode == 0 else []
        fingerprint = parts[1] if len(parts) >= 2 else ""
        key_type = parts[-1].strip("()").upper() if len(parts) >= 4 else ""

        mtime = priv_path.stat().st_mtime
        age_days = (datetime.now(timezone.utc) - datetime.fromtimestamp(mtime, tz=timezone.utc)).days

        stem = pub_path.stem
        if "__" in stem:
            alias, user = stem.split("__", 1)
        else:
            alias, user = stem, ""

        in_conf = str(priv_path) in conf_paths or str(pub_path) in conf_paths

        keys.append(LocalKey(
            stem=stem,
            alias=alias,
            user=user,
            fingerprint=fingerprint,
            key_type=key_type,
            pub_content=pub_content,
            age_days=age_days,
            in_local_conf=in_conf,
        ))
    return keys


def imported_stems() -> set[str]:
    """Stems of keys already imported to ~/.ssh/local/."""
    LOCAL_KEY_DIR.mkdir(parents=True, exist_ok=True)
    return {p.stem for p in LOCAL_KEY_DIR.glob("*.pub")
            if p.with_suffix("").exists()}


def import_from_bw(
    *,
    alias: str,
    user: str,
    hostname: str,
    port: str,
    private_key: str,
    public_key: str,
    add_to_conf: bool,
) -> LocalKey:
    """Write a BW SSH key to ~/.ssh/local/ and optionally add a local.conf entry."""
    LOCAL_KEY_DIR.mkdir(parents=True, exist_ok=True)
    LOCAL_KEY_DIR.chmod(0o700)

    stem = f"{alias}__{user}" if user else alias
    priv_path = LOCAL_KEY_DIR / stem
    pub_path  = LOCAL_KEY_DIR / f"{stem}.pub"

    if priv_path.exists():
        raise ValueError(f"'{stem}' is already imported in ~/.ssh/local/")

    priv_path.write_text(private_key if private_key.endswith("\n") else private_key + "\n")
    priv_path.chmod(0o600)
    pub_path.write_text(public_key if public_key.endswith("\n") else public_key + "\n")
    pub_path.chmod(0o644)

    if add_to_conf:
        _append_local_conf(alias=alias, user=user, hostname=hostname,
                           port=port or "22", priv_path=priv_path)

    fp_result = subprocess.run(
        ["ssh-keygen", "-l", "-E", "sha256", "-f", str(pub_path)],
        capture_output=True, text=True,
    )
    parts = fp_result.stdout.split() if fp_result.returncode == 0 else []

    return LocalKey(
        stem=stem,
        alias=alias,
        user=user,
        fingerprint=parts[1] if len(parts) >= 2 else "",
        key_type=parts[-1].strip("()").upper() if len(parts) >= 4 else "",
        pub_content=pub_path.read_text().strip(),
        age_days=0,
        in_local_conf=add_to_conf,
    )


def delete_local_key(stem: str) -> None:
    priv = LOCAL_KEY_DIR / stem
    pub  = LOCAL_KEY_DIR / f"{stem}.pub"
    for f in (priv, pub):
        if f.exists():
            f.unlink()


def _append_local_conf(*, alias: str, user: str, hostname: str, port: str, priv_path: Path) -> None:
    host_alias = f"{alias}::{user}" if user else alias
    lines = [
        f"\nHost {host_alias}",
        f"  HostName {hostname or '<replace.me>'}",
    ]
    if user:
        lines.append(f"  User {user}")
    lines += [
        f"  Port {port}",
        f"  IdentityFile {priv_path}",
        "  IdentitiesOnly yes",
        "",
    ]
    LOCAL_CONF.touch()
    with LOCAL_CONF.open("a") as f:
        f.write("\n".join(lines) + "\n")
