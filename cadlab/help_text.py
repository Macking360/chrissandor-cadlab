from __future__ import annotations

import textwrap

from . import APP_NAME, AUTHOR, BRAND, COURSE, VERSION


def full_help(home: str) -> str:
    return textwrap.dedent(f"""
    ATTRIBUTION
      {AUTHOR} / {BRAND} / {COURSE}

    PURPOSE
      A local-first, cross-platform engineering workspace. It organizes CAD
      projects, generates simple parts (STL, DXF, SVG) without any CAD package,
      runs a private PKI laboratory, and can cryptographically seal a project so
      later tampering is detectable. It runs as an ordinary user on Windows,
      macOS, Linux, WSL and Termux; no administrator or root rights are needed.

    THE THREE-PART FAMILY (open standards only, no shared code)
      crystalline-pki  The authority. Signs certificate requests, issues and
                       revokes certificates, publishes revocation lists.
      ChrisSandor CADLab  The workspace (this program). Creates a key and a
                       PKCS#10 request, imports the certificate the authority
                       returns, then signs a manifest of a project's files.
      OverWatch        The witness. Watches the project's files and receives
                       CADLab's verification results as events.
      The only things passed between them are PEM files, PKCS#10 requests, X.509
      certificates, CRLs and a plain JSON event over HTTP(S).

    PKI WORKFLOW (its own two-level lab CA)
      1. pki init-root           Self-signed Root CA (RSA 3072, encrypted key).
      2. pki init-intermediate   Intermediate CA signed by the Root.
      3. pki issue server|client Leaf certificates (server certs always get a SAN).
      4. pki sign-csr            Sign a request made elsewhere (no private key seen).
      5. pki verify              Chain, dates, CA flags, path length and CRL.
      6. pki revoke / crl        Record revocation, publish a signed CRL.
      7. pki renew               New key and serial; optionally revoke the old one.

    IDENTITY AND PROJECT SEAL
      identity create NAME       Key (encrypted) + PKCS#10 request. Send the
                                 request to any authority, for example:
                                   crystalline-pki issue-csr NAME/csr.pem
      identity import NAME CERT  Attach the issued certificate (and chain).
      project seal P --identity  Sign SHA-256 hashes of every file in project P.
      project verify P --trust   Check signature, signer chain to your root, CRL,
                                 and report modified, added and missing files.
      Exit status 0 = intact, 2 = tampered or untrusted, 1 = error.

    OVERWATCH LINK
      overwatch enroll --server URL --enroll-key KEY   Obtain a device token.
      project verify P --report                        Send the result to OverWatch.
      project watch-hint P                             Print the agent command that
                                                       watches the project's files.
      OverWatch does not validate client certificates; revocation there is by
      device token. A CRL here does not by itself disconnect an OverWatch agent.

    SECURITY AND LIMITATIONS
      - Private keys are encrypted PKCS#8 files. Passwords are prompted, never
        stored. CADLAB_PASSWORD (12+ characters) supplies one for unattended use;
        that exposes it to the process environment, so use it only for tests.
      - Keep the Root CA key offline where practical. This is a private lab CA,
        not a publicly trusted one. Never use it to impersonate public services.
      - The chain verifier checks signatures, dates, CA flag, key usage, path
        length and CRLs. It is not a full RFC 5280 engine: no name constraints,
        policies, OCSP or AIA fetching.
      - A CRL protects nothing until relying systems fetch and check it.
      - The audit log is hash-chained: edits and deletions in the middle are
        detected. Removing records from the very end is not; note the head hash.
      - Seals hash raw bytes. Tools that rewrite line endings or timestamps will
        make files appear modified.
      - Backups contain encrypted keys and the OverWatch device token.

    PLATFORMS
      Data lives under: {home}
      Windows : %LOCALAPPDATA%\\ChrisSandor\\CADLab, folder restricted with icacls
      macOS   : ~/Library/Application Support/ChrisSandor CADLab
      Linux   : $XDG_DATA_HOME or ~/.local/share/chrissandor-cadlab, mode 0700
      Termux  : the Linux layout; optional proot-distro Ubuntu helper
      Override with CADLAB_HOME or --home. Python 3.9+; cryptography 42+.

    COMMON COMMANDS
      cadlab                       interactive menu
      cadlab setup | diagnostics | help | maintenance | cleanup
      cadlab pki ... | identity ... | project ... | overwatch ... | backup ...
      cadlab --json <command>      machine-readable output where supported

    MAIN MENU
       1 PKI laboratory          2 Create CAD project      3 List CAD projects
       4 Termux PRoot helper     5 System diagnostics      6 Maintenance checks
       7 Clean runtime files     8 Create backup           9 List backups
      10 Verify backups         11 Setup wizard           12 Help
      13 Identities             14 Seal and verify project 15 OverWatch link
       0 Exit

    {APP_NAME} {VERSION}
    """).strip()
