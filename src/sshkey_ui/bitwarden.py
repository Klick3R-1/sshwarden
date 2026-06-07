"""Thin wrapper around the bw CLI. All calls pass --session explicitly."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

BW_BIN = "/usr/local/bin/bw"
SESSION_FILE = Path.home() / ".config" / "sshkey-ui" / "session.json"
SESSION_MAX_DAYS = 30

# ---------------------------------------------------------------------------
# In-process TTL caches
# ---------------------------------------------------------------------------
_ITEMS_TTL  = 30   # seconds — full vault list
_STATUS_TTL = 60   # seconds — is_unlocked check

_items_cache:  tuple[float, list] | None = None
_status_cache: tuple[float, bool] | None = None


def invalidate_cache() -> None:
    """Call after any write operation (sync, migrate, create)."""
    global _items_cache, _status_cache
    _items_cache  = None
    _status_cache = None

# Bitwarden SSH key item type
BW_TYPE_SSH_KEY = 5


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def _load_session() -> str | None:
    """Return stored session token if present and not expired."""
    if not SESSION_FILE.exists():
        return None
    try:
        data = json.loads(SESSION_FILE.read_text())
        token = data.get("token", "")
        created = datetime.fromisoformat(data["created_at"])
        age = (datetime.now(timezone.utc) - created).days
        if age >= SESSION_MAX_DAYS:
            SESSION_FILE.unlink(missing_ok=True)
            return None
        return token or None
    except Exception:
        return None


def _save_session(token: str) -> None:
    SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.write_text(
        json.dumps({"token": token, "created_at": datetime.now(timezone.utc).isoformat()})
    )
    SESSION_FILE.chmod(0o600)


def clear_session() -> None:
    SESSION_FILE.unlink(missing_ok=True)


def get_session() -> str | None:
    return _load_session()


def unlock(master_password: str) -> str:
    """Unlock the vault with master_password; return session token or raise."""
    env = {**os.environ, "BW_MASTER_PASSWORD": master_password}
    result = subprocess.run(
        [BW_BIN, "unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"],
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BWError(result.stderr.strip() or "unlock failed")
    token = result.stdout.strip()
    _save_session(token)
    return token


def lock(session: str) -> None:
    subprocess.run([BW_BIN, "lock", "--session", session], capture_output=True)
    clear_session()


def is_unlocked(session: str | None) -> bool:
    """Return True if the session token is valid and vault is unlocked."""
    global _status_cache
    if not session:
        return False
    now = time.monotonic()
    if _status_cache and (now - _status_cache[0]) < _STATUS_TTL:
        return _status_cache[1]
    result = subprocess.run(
        [BW_BIN, "status", "--session", session],
        capture_output=True,
        text=True,
    )
    ok = result.returncode == 0 and json.loads(result.stdout).get("status") == "unlocked"
    _status_cache = (now, ok)
    return ok


# ---------------------------------------------------------------------------
# Item data model
# ---------------------------------------------------------------------------

@dataclass
class SSHKeyItem:
    id: str
    name: str
    public_key: str
    fingerprint: str
    created_at: datetime | None

    # custom fields (new convention)
    alias: str = ""
    user: str = ""
    hostname: str = ""
    port: str = "22"
    password: str = ""

    # set by parser.py for unmigrated items
    migrated: bool = True
    # non-null when item belongs to a Bitwarden organisation/shared vault
    organization_id: str = ""

    @property
    def is_simple(self) -> bool:
        """True for keys that have no server info (e.g. GitHub, AUR). Valid but no deployment tracking."""
        return not self.hostname

    @property
    def is_shared(self) -> bool:
        return bool(self.organization_id)

    @property
    def host_alias(self) -> str:
        """SSH config Host value."""
        return f"{self.alias}--{self.user}" if self.user else self.alias

    @property
    def pub_filename(self) -> str:
        return f"{self.host_alias.replace('--', '__')}.pub"

    @property
    def age_days(self) -> int | None:
        if self.created_at is None:
            return None
        return (datetime.now(timezone.utc) - self.created_at).days

    @property
    def age_label(self) -> str:
        days = self.age_days
        if days is None:
            return "unknown"
        if days < 30:
            return f"{days}d"
        if days < 365:
            return f"{days // 30}mo"
        years, remainder = divmod(days, 365)
        months = remainder // 30
        return f"{years}y {months}mo" if months else f"{years}y"

    @property
    def age_color(self) -> str:
        days = self.age_days
        if days is None:
            return "secondary"
        if days < 180:
            return "ok"
        if days < 365:
            return "warn"
        return "danger"


# ---------------------------------------------------------------------------
# bw CLI calls
# ---------------------------------------------------------------------------

class BWError(Exception):
    pass


def _bw(*args: str, session: str) -> str:
    result = subprocess.run(
        [BW_BIN, *args, "--session", session],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BWError(result.stderr.strip() or f"bw {args[0]} failed")
    return result.stdout.strip()


def list_ssh_items(session: str, *, force: bool = False) -> list[SSHKeyItem]:
    """Return all SSH key items (type 5) from the vault."""
    global _items_cache
    now = time.monotonic()
    if not force and _items_cache and (now - _items_cache[0]) < _ITEMS_TTL:
        return _items_cache[1]

    from sshkey_ui.parser import parse_item_name

    raw = _bw("list", "items", "--nointeraction", session=session)
    items: list[SSHKeyItem] = []
    for obj in json.loads(raw or "[]"):
        if obj.get("type") != BW_TYPE_SSH_KEY:
            continue
        ssh = obj.get("sshKey", {})
        pub = ssh.get("publicKey", "")
        fp = ssh.get("fingerprint", "")
        created_str = obj.get("creationDate")
        try:
            created = datetime.fromisoformat(created_str.rstrip("Z") + "+00:00") if created_str else None
        except Exception:
            created = None

        # read custom fields
        fields: dict[str, str] = {}
        for f in obj.get("fields", []):
            fname = (f.get("name") or "").lower()
            fields[fname] = f.get("value") or ""

        item_name = (obj.get("name") or "").strip()
        org_id = obj.get("organizationId") or ""
        migrated = "alias" in fields

        if migrated:
            alias = fields.get("alias", "")
            user = fields.get("user", "")
            hostname = fields.get("hostname", "")
            port = fields.get("port", "22") or "22"
            password = fields.get("password", "")
        else:
            parsed = parse_item_name(item_name)
            alias = parsed["alias"]
            user = parsed["user"]
            hostname = parsed["hostname"]
            port = parsed["port"] or "22"
            password = ""

        # fallback alias from fingerprint for nameless items — never silently drop
        if not alias:
            alias = f"bw_{fp[:12]}" if fp else f"bw_{obj['id'][:8]}"

        items.append(SSHKeyItem(
            id=obj["id"],
            name=item_name,
            public_key=pub,
            fingerprint=fp,
            created_at=created,
            alias=alias,
            user=user,
            hostname=hostname,
            port=port,
            password=password,
            migrated=migrated,
            organization_id=org_id,
        ))
    _items_cache = (time.monotonic(), items)
    return items


def get_item_password(item_id: str, session: str) -> str:
    """Fetch the hidden password field for a single item."""
    raw = _bw("get", "item", item_id, "--nointeraction", session=session)
    obj = json.loads(raw)
    for f in obj.get("fields", []):
        if (f.get("name") or "").lower() == "password":
            return f.get("value") or ""
    return ""


def get_item_private_key(item_id: str, session: str) -> str:
    """Fetch the private key for a single SSH key item."""
    raw = _bw("get", "item", item_id, "--nointeraction", session=session)
    return json.loads(raw).get("sshKey", {}).get("privateKey", "")


def create_ssh_item(
    *,
    name: str,
    private_key: str,
    public_key: str,
    fingerprint: str,
    alias: str,
    user: str,
    hostname: str,
    port: str,
    password: str,
    session: str,
) -> str:
    """Create a new SSH key item in Bitwarden. Returns the new item id."""
    fields = [
        {"name": "alias",    "value": alias,    "type": 0},
        {"name": "user",     "value": user,     "type": 0},
        {"name": "hostname", "value": hostname, "type": 0},
        {"name": "port",     "value": port,     "type": 0},
    ]
    if password:
        fields.append({"name": "password", "value": password, "type": 1})  # type 1 = hidden

    payload = {
        "type": BW_TYPE_SSH_KEY,
        "name": name,
        "sshKey": {
            "privateKey": private_key,
            "publicKey": public_key,
            "keyFingerprint": fingerprint,  # BW input uses keyFingerprint; output serialises as fingerprint
        },
        "fields": fields,
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    result = subprocess.run(
        [BW_BIN, "create", "item", "--session", session],
        input=encoded,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BWError(result.stderr.strip() or "create item failed")
    return json.loads(result.stdout.strip())["id"]


_PROTECTED_FIELDS = {"alias", "user", "hostname", "port", "password"}


def get_item_custom_fields(item_id: str, session: str) -> tuple[str, list[dict]]:
    """Return (item_name, non-protected fields) for the fields editor."""
    raw = _bw("get", "item", item_id, "--nointeraction", session=session)
    obj = json.loads(raw)
    custom = [
        f for f in obj.get("fields", [])
        if (f.get("name") or "").lower() not in _PROTECTED_FIELDS
    ]
    return obj.get("name", ""), custom


def update_item_custom_fields(item_id: str, new_fields: list[dict], session: str) -> None:
    """Replace non-protected fields, preserving alias/user/hostname/port/password."""
    raw = _bw("get", "item", item_id, "--nointeraction", session=session)
    obj = json.loads(raw)
    protected = [
        f for f in obj.get("fields", [])
        if (f.get("name") or "").lower() in _PROTECTED_FIELDS
    ]
    obj["fields"] = protected + new_fields
    encoded = base64.b64encode(json.dumps(obj).encode()).decode()
    result = subprocess.run(
        [BW_BIN, "edit", "item", item_id, "--session", session],
        input=encoded, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise BWError(result.stderr.strip() or "edit item failed")


def migrate_item(
    item_id: str,
    *,
    alias: str,
    user: str,
    hostname: str,
    port: str,
    session: str,
) -> None:
    """Write custom fields onto an existing (unmigrated) item."""
    raw = _bw("get", "item", item_id, "--nointeraction", session=session)
    obj = json.loads(raw)

    existing = [f for f in obj.get("fields", [])
                if (f.get("name") or "").lower() not in ("alias", "user", "hostname", "port")]
    existing += [
        {"name": "alias",    "value": alias,    "type": 0},
        {"name": "user",     "value": user,     "type": 0},
        {"name": "hostname", "value": hostname, "type": 0},
        {"name": "port",     "value": port,     "type": 0},
    ]
    obj["fields"] = existing
    obj["name"] = f"{alias}--{user}" if user else alias

    encoded = base64.b64encode(json.dumps(obj).encode()).decode()
    result = subprocess.run(
        [BW_BIN, "edit", "item", item_id, "--session", session],
        input=encoded,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BWError(result.stderr.strip() or "edit item failed")
