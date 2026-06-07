# sshwarden

A local web dashboard for managing SSH keys stored in Bitwarden. Handles key syncing to `~/.ssh/bwpub/`, SSH config generation, local key imports, key creation, and custom fields editing.

Built with FastAPI, HTMX, and PicoCSS. Runs as a systemd user service at `http://sshkeys` via an nginx reverse proxy.

See [INSTALL.md](INSTALL.md) for setup instructions.

## Security

This tool is designed to run locally on a single-user workstation. The threat model assumes you are the only interactive user on the machine.

### What is protected

- **Session token** stored at `~/.config/sshwarden/session.json` with `chmod 600`. Plaintext, but readable only by your user — the same approach used by most CLI credential stores.
- **Public key files** in `~/.ssh/bwpub/` are stored with `chmod 600` because OpenSSH treats any `IdentityFile` path as a private key and rejects world-readable files.
- **No shell injection** — all `subprocess` calls use argument lists, never `shell=True`.
- **Bitwarden master password** is passed via environment variable to a subprocess and is not logged or stored.

### Known limitations

- **No authentication on the web UI.** Anyone who can reach `http://localhost:8765` (or `http://sshkeys` if you added the `/etc/hosts` entry) can use the interface. On a single-user workstation this is acceptable. Do not expose port 8765 or the nginx vhost beyond loopback.
- **Private key briefly touches disk during key creation.** `ssh-keygen` writes the key to a temporary file which is unlinked immediately after being uploaded to Bitwarden. `unlink()` does not overwrite the data — residual bytes may remain in unallocated disk blocks. If this matters for your threat model, mount `~/.ssh/` on tmpfs before creating keys.
- **SSH config injection via vault fields.** `hostname`, `user`, and `port` custom fields are written into `bwpub.auto.conf` without sanitization beyond the host alias. If an attacker has write access to your Bitwarden vault (compromised account, shared org vault), they could inject SSH config directives. This requires prior vault compromise.

### HTTP only (intentional)

The nginx proxy uses plain HTTP on loopback. TLS on `127.0.0.1` provides no meaningful protection and adds certificate management overhead. If you need to expose this over a network, put it behind a proper reverse proxy with TLS and authentication.
