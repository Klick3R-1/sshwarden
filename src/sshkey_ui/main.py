"""sshkey-ui — FastAPI web application."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, select_autoescape

from sshkey_ui import bitwarden as bw
from sshkey_ui import manifest as mf
from sshkey_ui import deployment as dep
from sshkey_ui import config_reader as cr
from sshkey_ui import local_keys as lk
from sshkey_ui.sync import run_sync, run_clear

TEMPLATES_DIR = Path(__file__).parent / "templates"
def _user_color(user: str) -> str:
    """Deterministic HSL color from username — same user always same color."""
    hue = sum(ord(c) * (i + 1) for i, c in enumerate(user)) % 360
    return f"hsl({hue}, 60%, 62%)"

_jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
    cache_size=0,  # workaround for Jinja2 LRU cache bug on Python 3.14
)
_jinja_env.filters["user_color"] = _user_color
templates = Jinja2Templates(env=_jinja_env)

app = FastAPI(title="sshkey-ui")

PORT = 8765


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _session(request: Request) -> str | None:
    return bw.get_session()


def _local_key_stems() -> set[str]:
    """Stems of keys imported to ~/.ssh/local/ — used to badge rows on the dashboard."""
    return lk.imported_stems()


def _agent_fingerprints() -> set[str]:
    """Return fingerprints currently loaded in the SSH agent."""
    try:
        result = subprocess.run(
            ["ssh-add", "-l", "-E", "sha256"],
            capture_output=True, text=True,
        )
        fps: set[str] = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("SHA256:"):
                fps.add(parts[1])
        return fps
    except Exception:
        return set()


def _redirect_unlock() -> RedirectResponse:
    return RedirectResponse(url="/unlock", status_code=302)


# ---------------------------------------------------------------------------
# Unlock / lock
# ---------------------------------------------------------------------------

@app.get("/unlock", response_class=HTMLResponse)
async def unlock_page(request: Request, error: str = ""):
    return templates.TemplateResponse(request, "unlock.html", {"error": error})


@app.post("/unlock")
async def do_unlock(password: Annotated[str, Form()]):
    try:
        bw.unlock(password)
    except bw.BWError as e:
        return RedirectResponse(url=f"/unlock?error={e}", status_code=302)
    return RedirectResponse(url="/", status_code=302)


@app.post("/lock")
async def do_lock(request: Request):
    session = _session(request)
    if session:
        bw.lock(session)
    return RedirectResponse(url="/unlock", status_code=302)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()
    return templates.TemplateResponse(request, "index.html")


@app.get("/keys", response_class=HTMLResponse)
async def keys_partial(request: Request, show_shared: bool = False):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return HTMLResponse('<p class="error">Session expired — <a href="/unlock">unlock</a></p>')

    items = bw.list_ssh_items(session)
    if not show_shared:
        items = [i for i in items if not i.is_shared]

    agent_fps = _agent_fingerprints()
    local_stems = _local_key_stems()
    deployments = mf.load()

    rows = []
    for item in items:
        dep_status = dep.manifest_status(item, deployments)
        rows.append({
            "item": item,
            "agent": item.fingerprint in agent_fps,
            "dep_status": dep_status,
            "has_local_key": item.pub_filename.removesuffix(".pub") in local_stems,
        })

    return templates.TemplateResponse(request, "partials/key_table.html", {"rows": rows})


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------

@app.post("/sync", response_class=HTMLResponse)
async def do_sync(request: Request):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()

    bw.invalidate_cache()
    lines: list[str] = []
    try:
        for line in run_sync(session, clean=True):
            lines.append(line)
    except bw.BWError as e:
        lines.append(f"[ERROR] {e}")

    output = "\n".join(lines)
    return templates.TemplateResponse(request, "partials/sync_log.html", {"output": output})


@app.post("/clear", response_class=HTMLResponse)
async def do_clear(request: Request):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()

    lines: list[str] = list(run_clear())
    output = "\n".join(lines)
    return templates.TemplateResponse(request, "partials/sync_log.html", {"output": output})


# ---------------------------------------------------------------------------
# Deployment check
# ---------------------------------------------------------------------------

@app.post("/keys/{item_id}/check", response_class=HTMLResponse)
async def check_key(request: Request, item_id: str):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()

    items = bw.list_ssh_items(session)
    item = next((i for i in items if i.id == item_id), None)
    if not item:
        return HTMLResponse("Not found", status_code=404)

    status, log_lines = await dep.live_check(item)
    agent_fps = _agent_fingerprints()
    local_stems = _local_key_stems()

    return templates.TemplateResponse(request, "partials/check_result.html", {
        "item": item,
        "agent": item.fingerprint in agent_fps,
        "dep_status": status,
        "has_local_key": item.pub_filename.removesuffix(".pub") in local_stems,
        "log": "\n".join(log_lines),
    })


@app.post("/keys/check-all", response_class=HTMLResponse)
async def check_all(request: Request):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()

    items = bw.list_ssh_items(session)
    agent_fps = _agent_fingerprints()
    local_stems = _local_key_stems()
    deployments = mf.load()

    rows = []
    all_logs: list[str] = []
    for item in items:
        status, log_lines = await dep.live_check(item)
        rows.append({
            "item": item,
            "agent": item.fingerprint in agent_fps,
            "dep_status": status,
            "has_local_key": item.pub_filename.removesuffix(".pub") in local_stems,
        })
        all_logs.extend(log_lines)

    return templates.TemplateResponse(request, "partials/check_all_result.html", {
        "rows": rows,
        "log": "\n".join(all_logs),
    })


# ---------------------------------------------------------------------------
# Password reveal
# ---------------------------------------------------------------------------

@app.get("/keys/{item_id}/password", response_class=HTMLResponse)
async def reveal_password(request: Request, item_id: str):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return HTMLResponse("locked")
    try:
        pwd = bw.get_item_password(item_id, session)
    except bw.BWError:
        pwd = ""
    return HTMLResponse(f'<code>{pwd or "(none)"}</code>')


# ---------------------------------------------------------------------------
# Migrate item
# ---------------------------------------------------------------------------

@app.post("/keys/{item_id}/migrate", response_class=HTMLResponse)
async def migrate_item(
    request: Request,
    item_id: str,
    alias: Annotated[str, Form()],
    user: Annotated[str, Form()],
    hostname: Annotated[str, Form()],
    port: Annotated[str, Form()] = "22",
):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()

    try:
        bw.migrate_item(item_id, alias=alias, user=user, hostname=hostname, port=port, session=session)
        bw.invalidate_cache()
    except bw.BWError as e:
        return HTMLResponse(f'<span class="error">{e}</span>')

    items = bw.list_ssh_items(session)
    item = next((i for i in items if i.id == item_id), None)
    if not item:
        return HTMLResponse("ok")

    agent_fps = _agent_fingerprints()
    local_stems = _local_key_stems()
    deployments = mf.load()
    return templates.TemplateResponse(request, "partials/key_row.html", {
        "item": item,
        "has_local_key": item.pub_filename.removesuffix(".pub") in local_stems,
        "agent": item.fingerprint in agent_fps,
        "dep_status": dep.manifest_status(item, deployments),
    })


# ---------------------------------------------------------------------------
# Key creation
# ---------------------------------------------------------------------------

@app.post("/keys/create", response_class=HTMLResponse)
async def create_key(
    request: Request,
    alias: Annotated[str, Form()],
    user: Annotated[str, Form()],
    hostname: Annotated[str, Form()],
    port: Annotated[str, Form()] = "22",
    password: Annotated[str, Form()] = "",
    key_type: Annotated[str, Form()] = "ed25519",
):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()

    import tempfile, os, stat

    error = ""
    try:
        with tempfile.NamedTemporaryFile(prefix="sshkey_", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        tmp_path.unlink()  # ssh-keygen must create it fresh; existing file triggers overwrite prompt

        try:
            comment = f"{alias} {user}"
            result = subprocess.run(
                ["ssh-keygen", "-t", key_type, "-f", str(tmp_path), "-N", "", "-C", comment],
                capture_output=True, text=True, stdin=subprocess.DEVNULL,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr or f"ssh-keygen exited {result.returncode}")

            private_key = tmp_path.read_text()
            public_key = Path(str(tmp_path) + ".pub").read_text().strip()

            fp_result = subprocess.run(
                ["ssh-keygen", "-l", "-E", "sha256", "-f", str(tmp_path) + ".pub"],
                capture_output=True, text=True,
            )
            parts = fp_result.stdout.split()
            fingerprint = parts[1] if fp_result.returncode == 0 and len(parts) >= 2 else ""

            if not fingerprint:
                import hashlib, base64 as _b64
                try:
                    pk_parts = public_key.split()
                    key_bytes = _b64.b64decode(pk_parts[1])
                    digest = hashlib.sha256(key_bytes).digest()
                    fingerprint = "SHA256:" + _b64.b64encode(digest).decode().rstrip("=")
                except Exception:
                    pass

            bw.create_ssh_item(
                name=f"{alias} {user}",
                private_key=private_key,
                public_key=public_key,
                fingerprint=fingerprint,
                alias=alias,
                user=user,
                hostname=hostname,
                port=port,
                password=password,
                session=session,
            )
        finally:
            subprocess.run(["shred", "-u", str(tmp_path)], capture_output=True)
            pub = Path(str(tmp_path) + ".pub")
            if pub.exists():
                pub.unlink()

        bw.invalidate_cache()
        for _ in run_sync(session):
            pass

    except Exception as e:
        error = str(e) or type(e).__name__

    if error:
        return templates.TemplateResponse(request, "partials/create_error.html", {"error": error})
    return RedirectResponse(url="/", status_code=302)


# ---------------------------------------------------------------------------
# Manifest editor
# ---------------------------------------------------------------------------

@app.get("/manifest", response_class=HTMLResponse)
async def manifest_page(request: Request):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()
    deployments = mf.load()
    items = bw.list_ssh_items(session)
    return templates.TemplateResponse(request, "manifest.html", {
        "deployments": deployments,
        "items": items,
    })


@app.post("/manifest")
async def save_manifest(request: Request):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()
    form = await request.form()
    aliases = form.getlist("alias")
    users = form.getlist("user")
    entries = [{"alias": a, "user": u} for a, u in zip(aliases, users) if a.strip()]
    mf.save(entries)
    return RedirectResponse(url="/manifest", status_code=302)


# ---------------------------------------------------------------------------
# Config overview
# ---------------------------------------------------------------------------

@app.get("/config", response_class=HTMLResponse)
async def config_page(request: Request):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()
    auto, local = cr.load()
    local_hosts = set(local.keys())
    local_only  = local_hosts - set(auto.keys())
    hosts = sorted(set(auto.keys()) | local_hosts)
    first = hosts[0] if hosts else None
    first_detail = _build_detail(first, auto, local) if first else {}
    return templates.TemplateResponse(request, "config.html", {
        "hosts": hosts,
        "local_hosts": local_hosts,
        "local_only": local_only,
        "selected": first,
        "detail": first_detail,
    })


@app.get("/config/detail", response_class=HTMLResponse)
async def config_detail(request: Request, host: str = ""):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return HTMLResponse("")
    auto, local = cr.load()
    detail = _build_detail(host, auto, local)
    return templates.TemplateResponse(request, "partials/config_detail.html", {
        "host": host,
        "detail": detail,
    })


def _build_detail(
    host: str | None,
    auto: dict[str, dict[str, str]],
    local: dict[str, dict[str, str]],
) -> list[dict]:
    """Merge auto + local directives into a list of {key, value, source} dicts."""
    if not host:
        return []
    rows = []
    seen: set[str] = set()
    for key, value in (local.get(host) or {}).items():
        rows.append({"key": key, "value": value, "source": "local"})
        seen.add(key.lower())
    for key, value in (auto.get(host) or {}).items():
        if key.lower() not in seen:
            rows.append({"key": key, "value": value, "source": "auto"})
    return rows


# ---------------------------------------------------------------------------
# Local keys
# ---------------------------------------------------------------------------

@app.get("/local-keys", response_class=HTMLResponse)
async def local_keys_page(request: Request):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()
    keys = lk.list_local_keys()
    bw_items = bw.list_ssh_items(session)
    already = lk.imported_stems()
    importable = [i for i in bw_items if i.alias and
                  (f"{i.alias}__{i.user}" if i.user else i.alias) not in already]
    return templates.TemplateResponse(request, "local_keys.html", {
        "keys": keys,
        "importable": importable,
    })


@app.post("/local-keys/import", response_class=HTMLResponse)
async def import_bw_key(
    request: Request,
    item_id:     Annotated[str,  Form()],
    hostname:    Annotated[str,  Form()] = "",
    port:        Annotated[str,  Form()] = "22",
    add_to_conf: Annotated[bool, Form()] = False,
):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()

    items = bw.list_ssh_items(session)
    item = next((i for i in items if i.id == item_id), None)
    if not item:
        return RedirectResponse(url="/local-keys?error=Item+not+found", status_code=302)

    try:
        private_key = bw.get_item_private_key(item_id, session)
        lk.import_from_bw(
            alias=item.alias,
            user=item.user,
            hostname=hostname or item.hostname,
            port=port or item.port or "22",
            private_key=private_key,
            public_key=item.public_key,
            add_to_conf=add_to_conf,
        )
    except Exception as e:
        keys = lk.list_local_keys()
        bw_items = bw.list_ssh_items(session)
        already = lk.imported_stems()
        importable = [i for i in bw_items if i.alias and
                      (f"{i.alias}__{i.user}" if i.user else i.alias) not in already]
        return templates.TemplateResponse(request, "local_keys.html", {
            "keys": keys, "importable": importable, "error": str(e),
        })
    return RedirectResponse(url="/local-keys", status_code=302)


@app.post("/local-keys/{stem}/delete", response_class=HTMLResponse)
async def delete_local_key(request: Request, stem: str):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()
    lk.delete_local_key(stem)
    return RedirectResponse(url="/local-keys", status_code=302)


# ---------------------------------------------------------------------------
# local.conf raw editor (Config page)
# ---------------------------------------------------------------------------

@app.get("/config/local-conf", response_class=HTMLResponse)
async def get_local_conf(request: Request):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return HTMLResponse("")
    content = cr.LOCAL_CONF.read_text() if cr.LOCAL_CONF.exists() else ""
    return templates.TemplateResponse(request, "partials/local_conf_editor.html",
                                      {"content": content})


@app.post("/config/local-conf", response_class=HTMLResponse)
async def save_local_conf(request: Request, content: Annotated[str, Form()]):
    session = _session(request)
    if not session or not bw.is_unlocked(session):
        return _redirect_unlock()
    cr.LOCAL_CONF.parent.mkdir(parents=True, exist_ok=True)
    cr.LOCAL_CONF.write_text(content.replace("\r\n", "\n").replace("\r", "\n"))
    cr.LOCAL_CONF.chmod(0o600)
    return RedirectResponse(url="/config", status_code=302)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def run() -> None:
    uvicorn.run("sshkey_ui.main:app", host="127.0.0.1", port=PORT, reload=False)


if __name__ == "__main__":
    run()
