# ChrisSandor CADLab

[![CI](https://github.com/Macking360/chrissandor-cadlab/actions/workflows/ci.yml/badge.svg)](https://github.com/Macking360/chrissandor-cadlab/actions/workflows/ci.yml)

A cross-platform command-line CAD workspace with a private PKI laboratory and **signed project seals**.
Runs on Windows, macOS, Linux and Termux. One dependency (`cryptography`).

By Chris Sandor / Macking360 / ChrisSandor Classes.

CADLab is the **workspace** layer of a three-part security base. The other two parts are separate public projects:

| Part | Role | Repository |
|---|---|---|
| **crystalline-pki** | **Authority** - issues and revokes certificates, publishes revocation lists | https://github.com/Macking360/crystalline-pki |
| **OverWatch** | **Witness** - watches files and devices, records events, alerts | https://github.com/Macking360/overwatch |
| **CADLab** (this repo) | **Workspace** - holds your design projects, signs them, proves they were not changed | https://github.com/Macking360/chrissandor-cadlab |

## How the three fit together

```
            crystalline-pki                     (who is allowed to sign / be trusted)
            issues certificates
            revokes + publishes CRL
               |                  \
   signed certificate + chain      \  CRL, root certificate
               v                    v
        CADLab (workspace)  ----------------->  anyone who verifies a seal
        makes key + CSR                          (trusted root + CRL = verdict)
        seals a project: signs a manifest
               |
               | one small JSON event over HTTP(S): "seal intact" / "seal broken"
               v
         OverWatch (witness)  <---- its own agent also watches the same files
         stores events, raises alerts
```

The important design choice: **the three projects share no code.** They talk through open standards only:

- **PEM / X.509 certificates, PKCS#10 certificate requests and CRLs** between CADLab and crystalline-pki.
- **A plain JSON event over HTTP(S)** between CADLab and OverWatch (`POST /api/enroll`, `POST /api/events`).

Because the links are standards and not private APIs, each part can be replaced, scaled or run on a different machine without touching the others. That is what makes this a *base* you can keep building on.

What each link proves, in one sentence each:

- **crystalline-pki -> CADLab:** the signing key belongs to someone the authority vouched for, and the authority can later say "no longer" (revocation).
- **CADLab -> verifier:** every file in the project has exactly the bytes that were signed, and the signer chains to a root you chose to trust.
- **CADLab -> OverWatch:** a failed or passed check becomes a recorded, alertable event instead of something only the person at the keyboard saw.
- **OverWatch (own agent) -> files:** an independent second witness sees the file change as it happens, without relying on CADLab being run.

## Where this is going (roadmap - not built yet)

The long-term aim is a larger layered system: multiple nodes, VPS and VM hosts, traffic flowing north-south and east-west, bidirectional piping and a mesh between nodes. This repository is **one foundation layer** of that, not the finished system.

What the base already gives you and what a multi-node system will need from it:

| Need in a multi-node system | Where the base stands today |
|---|---|
| A way to say who each node/service is | **Built:** certificates issued by crystalline-pki (including client certificates) |
| A way to remove a compromised node | **Built:** revocation + CRL; CADLab and any verifier honour it |
| Encrypted links between nodes (mutual TLS) | **Partly built:** crystalline-pki's lab demonstrates mutual TLS on one machine; not yet a multi-host deployment |
| Seeing what happens on each node | **Built for files:** OverWatch agents report events to one server. **Not yet:** east-west traffic monitoring |
| Tamper-evident records | **Built:** hash-chained audit trail, signed manifests |
| Node enrolment and rotation at scale | **Not built:** today enrolment is manual and per device |
| Mesh routing / bidirectional piping / VPS orchestration | **Not built.** Planned, not started in this repository |

Nothing in the table marked "not built" is claimed to work. They are the next layers, each of which will plug into the same certificate-and-event contract above.

## Install

```
python -m pip install .
cadlab --help
```

Or run without installing: `python ChrisSandor_CADLab.py` (interactive menu). Python 3.9 or newer.

On first use, if `cryptography` is missing, CADLab tells you exactly how to install it (it will not change your system unless you set `CADLAB_AUTO_INSTALL=1`).

## The workflow

```
# 1. Your own lab authority (or use crystalline-pki instead - see below)
cadlab pki init-root
cadlab pki init-intermediate

# 2. A signing identity: private key stays on your machine, only the request leaves
cadlab identity create alice
cadlab pki sign-csr ~/.local/share/chrissandor-cadlab/pki/identities/alice/csr.pem --kind client
cadlab identity import alice <issued cert> --chain <issued chain>

# 3. A project, with parts (STL / DXF / SVG written by pure-Python geometry)
cadlab project create bracket
cadlab project part bracket box base --size 40 20 10
cadlab project part bracket plate cover --size 60 30 --hole 10 10 5
cadlab project part bracket cylinder pin --size 3 12 --segments 32

# 4. Seal, then verify at any time
cadlab project seal bracket --identity alice
cadlab project verify bracket
```

`project verify` exit codes: `0` intact, `1` error, `2` tampered or untrusted. Use `--json` for machine-readable output.
A full recorded run is in [`docs/beta-run/`](docs/beta-run/).

### Using crystalline-pki as the authority

```
crystalline-pki init
cadlab identity create alice
crystalline-pki issue-csr <path to alice's csr.pem> --name alice
cadlab identity import alice <issued>/<serial>.pem --chain <issued>/<serial>-chain.pem
cadlab project seal bracket --identity alice

# verify against crystalline's root, and honour its revocation list
cadlab project verify bracket --trust <crystalline home>/pki/root/root-cert.pem --crl <crystalline home>/pki/crl/intermediate-crl.pem
```

After `crystalline-pki revoke alice` and `crystalline-pki crl refresh`, the same verify returns exit code `2` (untrusted signer). This exact flow is an automated test against the real tool.

### Reporting to OverWatch

```
cadlab overwatch enroll --server https://overwatch.example:8771 --enroll-key <key> [--ca-cert ca.pem]
cadlab project verify bracket --report          # sends a seal_verified / seal_violation event
cadlab project watch-hint bracket --server ...  # prints the OverWatch agent command that watches the sealed files
```

The device token is stored in `config/overwatch-token` with owner-only permissions, never in the settings file.

## Other features

- Private PKI lab: root and intermediate CA, TLS server and client certificates, SQLite inventory, revoke, CRL, verify, renew, export chain, expiry report, audit CSV.
- Encrypted private keys (PKCS#8), password of 12+ characters.
- Backups (SQLite online snapshot + SHA-256 sidecar), safe restore into an empty folder only.
- Diagnostics, maintenance (deletes nothing), runtime cleanup (old temp files only).
- Hash-chained audit trail of PKI actions.
- Interactive menu and a full non-interactive CLI.
- Termux/PRoot helper notes for running a Linux guest on Android.

## Where your data lives

| Platform | Location |
|---|---|
| Windows | `%LOCALAPPDATA%\ChrisSandor\CADLab` (restricted to your user with `icacls`) |
| macOS | `~/Library/Application Support/ChrisSandor CADLab` |
| Linux / Termux | `$XDG_DATA_HOME/chrissandor-cadlab` or `~/.local/share/chrissandor-cadlab` (mode 0700) |

Override with `--home DIR` or `CADLAB_HOME`. Environment: `CADLAB_PASSWORD` (non-interactive use and tests only - it sits in the process environment), `CADLAB_SKIP_ACL`, `CADLAB_AUTO_INSTALL`, `NO_COLOR`.

## What was tested

| Area | Result |
|---|---|
| Unit and CLI tests | 119 passed on Windows 11 / Python 3.12 (1 POSIX-permission test skipped there) and 119 passed on Linux (WSL Ubuntu, Python 3.12) |
| Interop with the real crystalline-pki | 2 tests: its issued certificate seals and verifies in CADLab; revoking it there makes the seal untrusted |
| Interop with the real OverWatch server | 2 tests: CADLab enrols, sends events, they are stored with the right severity; a wrong enrol key is refused |
| OverWatch agent watching a sealed file | Checked by hand: agent reported the modification event |
| `openssl verify -crl_check` on a CADLab chain | Part of the test suite (skipped if OpenSSL is absent) |
| Recorded end-to-end runs | [`docs/beta-run/windows.txt`](docs/beta-run/windows.txt), [`docs/beta-run/linux.txt`](docs/beta-run/linux.txt) |
| macOS | Tested only by GitHub Actions CI, not on physical hardware |
| Termux / Android | **Not tested.** The code paths are shared with Linux; the PRoot helper is untested |

CI runs the suite on Ubuntu, Windows and macOS with Python 3.9 and 3.12, plus a separate job with the two sibling projects.

## Limits you should know about

- The certificate-chain verifier checks signatures, dates, CA flags, key usage, path length and CRLs. It is **not a full RFC 5280 engine** (no name constraints, no policy processing, no OCSP).
- The audit trail is **tamper-evident, not tamper-proof**: editing or deleting a middle record is detected, but cutting off the end of the log is not.
- OverWatch does **not** verify client certificates; revoking a device there is done by its device token.
- Seals hash raw file bytes. Anything that rewrites a file (git `autocrlf` line-ending conversion, an editor that re-saves) will break the seal - which is correct, but may surprise you.
- Backups contain your encrypted private keys and the OverWatch token. Protect them like the keys themselves.
- Project names are strict (letters, digits, `.`, `_`, `-`). The interactive menu sanitises names for you; the CLI refuses bad ones.
- This is a learning and small-team tool. Do not use it as the only root of trust for production infrastructure.

## Development

```
python -m pip install -e . pytest
python -m pytest -q --ignore=tests/interop
# interop (needs the sibling projects):
python -m pip install "git+https://github.com/Macking360/crystalline-pki"
OVERWATCH_DIR=/path/to/overwatch python -m pytest -q tests/interop
python scripts/beta_scenario.py
```

## License

MIT - see [LICENSE](LICENSE).
