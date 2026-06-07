"""Fallback parser for unmigrated Bitwarden SSH key item names.

Mirrors the tokenisation rules from bw-ssh-pubsync:
  <alias> [<user>] [<port>] [<hostname_or_ip>]
"""

from __future__ import annotations

import re

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _is_ip(token: str) -> bool:
    return bool(_IP_RE.match(token))


def _looks_domain(token: str) -> bool:
    return "." in token


def parse_item_name(name: str) -> dict[str, str]:
    """Return dict with keys alias, user, port, hostname (all str, may be empty)."""
    tokens = name.strip().split()
    if not tokens:
        return {"alias": "", "user": "", "port": "", "hostname": ""}

    alias = re.sub(r"[^A-Za-z0-9._-]+", "_", tokens[0])

    port = ""
    hostname = ""
    user = ""

    # port = last numeric token in 1..65535
    for tok in reversed(tokens):
        if tok.isdigit() and 1 <= int(tok) <= 65535:
            port = tok
            break

    # hostname = first token (after alias) that looks like IP or contains a dot
    for tok in tokens[1:]:
        tl = tok.lower()
        if _is_ip(tl) or _looks_domain(tl):
            hostname = tl
            break

    # user = first non-numeric, non-host token after alias
    for tok in tokens[1:]:
        tl = tok.lower()
        if not tok.isdigit() and not _is_ip(tl) and not _looks_domain(tl):
            user = tok
            break

    return {"alias": alias, "user": user, "port": port, "hostname": hostname}
