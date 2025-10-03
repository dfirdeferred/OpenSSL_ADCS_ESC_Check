# OpenSSL_ADCS_ESC_Check
Use only OpenSSL to Heuristically detect ADCS vulnerabilities evidence for ESC1, ESC3, ESC6, ESC9, ESC10, ESC13, ESC15 by inspecting issued certificates (PEM/DER).

# AD CS ESC Indicator Scanners

Tools for triaging issued X.509 certificates for evidence of **AD CS misconfigurations** related to **ESC1, ESC3, ESC6, ESC9, ESC10, ESC13, ESC15**.

- **Scripts**:  
  - `esc_check.sh` — Bash CLI (Unix/WSL/Git Bash)  
  - `esc_check.py` — Python 3 CLI (Linux/macOS/Windows)
- **Input**: Cert **files or folders** containing `.cer`, `.crt`, `.pem`, or `.der`
- **Output**: Human-readable CLI, optional **HTML report**, optional **JSON** (Python)

> ⚠️ These tools analyze **certificate contents only**. Findings that depend on domain configuration (e.g., template flags, mapping rules) are marked **suspected** and must be verified in AD/AD CS.

---

## What these tools detect

| ESC | Heuristic from cert contents | OIDs/Clues |
|-----|-------------------------------|------------|
| **ESC1?** | Privileged-looking UPN in SAN; assumes vulnerable template allowed enrollee-supplied SAN | UPN SAN (`1.3.6.1.4.1.311.20.2.3`) + privileged regex |
| **ESC3** | Certificate Request Agent EKU present | `1.3.6.1.4.1.311.20.2.1` |
| **ESC6** | UPN SAN present (potential impersonation) | `1.3.6.1.4.1.311.20.2.3` |
| **ESC9** | No EKU extension (implicitly any purpose) | EKU block **absent** |
| **ESC10?** | Subject/SAN matches privileged regex (weak mapping risk) | Privileged regex hit |
| **ESC13** | Certificate Policies contains org-defined “danger” OIDs linked to privileged groups | Your OID list |
| **ESC15** | Application Policies present with **clientAuth** | MS App Policies `1.3.6.1.4.1.311.21.10` + `1.3.6.1.5.5.7.3.2` |

---

## Requirements

**Common**
- OpenSSL in PATH  
  - Linux/macOS: preinstalled or `brew install openssl`  
  - Windows: use **WSL** or **Git Bash** (Bash script), or ensure `openssl.exe` is in PATH (Python script also uses OpenSSL)

**Bash**
- `bash`, `grep`, `sed`, `find` (standard on Unix/Git Bash)

**Python**
- Python **3.8+** (no extra packages; uses `subprocess` to call `openssl`)

---

## Quick start

```bash
# Bash scanner
chmod +x esc_check.sh
./esc_check.sh ./certs

# Python scanner
python3 esc_check.py ./certs

# Command-line options
Bash — esc_check.sh
Usage: ./esc_check.sh [--danger-oids FILE] [--priv-pattern 'regex'] [--evidence] [--evidence-html out.html] <file-or-dir> [...]

--danger-oids FILE     File with one OID per line (flags ESC13 when matched)
--priv-pattern REGEX   Regex for privileged-looking identities (default matches Administrator, krbtgt, Domain Admins, etc.)
--evidence             Print exact blocks that triggered findings
--evidence-html FILE   Write a styled HTML report (self-contained)

# Python — esc_check.py
Usage: python3 esc_check.py [--danger-oids FILE] [--priv-pattern REGEX] [--json] [--evidence] [--evidence-html out.html] <file-or-dir> [...]

--danger-oids FILE     File with one OID per line (flags ESC13 when matched)
--priv-pattern REGEX   Regex for privileged-looking identities (default provided)
--json                 Emit JSON (suppresses human formatting unless also writing HTML)
--evidence             Include exact evidence blocks in CLI output
--evidence-html FILE   Write a styled HTML report (self-contained)

# Examples
## A) Basic scan (folder)
./esc_check.sh ./certs
python3 esc_check.py ./certs

## B) Add “dangerous” policy OIDs (ESC13)
Create esc13_oids.txt:
# OIDs mapped (in your AD) to privileged groups:
1.2.3.4.5.6
1.2.840.113556.1.8000.2554.1

## Run:
./esc_check.sh --danger-oids esc13_oids.txt ./certs
python3 esc_check.py --danger-oids esc13_oids.txt ./certs

## C) Tighten privileged identity regex (ESC10/ESC1 suspected)
./esc_check.sh --priv-pattern 'UPN=.*(admin@corp\.local|da@corp\.local)' ./certs
python3 esc_check.py --priv-pattern 'UPN=.*(admin@corp\.local|da@corp\.local)' ./certs

## D) Evidence + HTML report
./esc_check.sh --evidence --evidence-html report.html ./certs
python3 esc_check.py --evidence --evidence-html report.html ./certs

## E) JSON output (for automation)
python3 esc_check.py --json ./certs > findings.json

## Output & interpretation
CLI (abbreviated)
[./certs/user.cer]
  Subject: CN=NormalUser, OU=Corp, DC=corp, DC=local
  Policy OIDs: 1.2.3.4.5.6
  Flags: ESC6, ESC13
   - ESC6: UPN SAN present.
   - ESC13: Dangerous policy OIDs present: 1.2.3.4.5.6

ESC6 → cert contains a UPN SAN (verify expected vs. impersonation)

ESC13 → cert’s Policy OIDs includes an OID you listed as dangerous

Evidence mode (--evidence): also prints the exact Subject, SAN, EKU, Policies, Application Policies blocks that triggered flags.

HTML report (--evidence-html): one card per certificate with the same evidence — easy to paste into slides or attach to an incident ticket.

# Red vs. Blue follow-ups
| Flag       | Red Team next step                                            | Blue Team next step                                                                                             |
| ---------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **ESC1?**  | Request SAN as target UPN; attempt auth (if template allowed) | Disable/limit “enrollee supplies subject/SAN”; monitor privileged UPN issuance                                  |
| **ESC3**   | Use agent cert to enroll on behalf of others (CMC/certreq)    | Restrict agent templates; audit approvals; alert on EKU OID `1.3.6.1.4.1.311.20.2.1`                            |
| **ESC6**   | Forge UPN SAN in CSR to impersonate                           | Validate SAN UPN vs requester; require approvals; alert on privileged UPNs                                      |
| **ESC9**   | Use for unintended auth if chain trusted                      | Enforce EKUs on templates; reissue/replace lax certs                                                            |
| **ESC10?** | Aim CN/UPN at loose DC mapping rules                          | Enforce strict UPN mapping; remove wildcard/loose explicit mappings                                             |
| **ESC13**  | Include those policy OIDs in CSR to gain mapped claims        | Search `CN=OID,...` for `msDS-OIDToGroupLink`; unlink privileged groups                                         |
| **ESC15**  | Inject Application Policies with `clientAuth` (EKUwu)         | Avoid v1 templates; block requester-supplied extensions; alert on `1.3.6.1.4.1.311.21.10` + `1.3.6.1.5.5.7.3.2` |


# Handy OpenSSL snippets
# SAN block
openssl x509 -in file.crt -text -noout | sed -n '/Subject Alternative Name/,+3p'

# EKUs
openssl x509 -in file.crt -text -noout | sed -n '/Extended Key Usage/,+2p'

# Certificate Policies (for ESC13 review)
openssl x509 -in file.crt -text -noout | sed -n '/Certificate Policies/,+12p'

# Any Purpose EKU (ESC2 context)
openssl x509 -in file.crt -text -noout | grep -Ei "Any Purpose|2\.5\.29\.37\.0"

# Application Policies (ESC15)
openssl x509 -in file.crt -text -noout | grep -A3 "1\.3\.6\.1\.4\.1\.311\.21\.10"

# Windows usage notes

Bash script: run via WSL or Git Bash

Python script: run in PowerShell/CMD (ensure openssl.exe is in PATH)

Export certs from Windows stores (certmgr.msc) as Base-64 or DER

## Troubleshooting

“Not a readable certificate (PEM/DER)”
Convert and retry:

openssl x509 -in file.cer -inform der -out file.pem


No flags, but still suspicious
Some ESCs are configuration-driven; investigate AD CS templates, CA settings, and DC certificate mapping.

## Example files

esc13_oids.txt — your list of dangerous policy OIDs (one per line)

examples/ — optional scripts to generate sample certs and build HTML reports

Run:
cd examples
./make_samples.sh     # creates sample certs in examples/certs
./run_examples.sh     # runs both scanners and writes HTML reports

Reports: examples/report_bash.html, examples/report_py.html

## Security & operational guidance

Treat ESC1?/ESC10? as leads; confirm against template/DC mapping configuration.

Maintain an org-specific privileged identity regex and danger OID list.

Automate periodic scans; diff results and alert on new flags.





