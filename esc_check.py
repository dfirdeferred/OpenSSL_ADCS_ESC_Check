#!/usr/bin/env python3
import argparse, re, subprocess, json
from pathlib import Path
from html import escape

OID_UPN = "1.3.6.1.4.1.311.20.2.3"
OID_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
OID_APP_POLICIES = "1.3.6.1.4.1.311.21.10"
OID_CLIENTAUTH = "1.3.6.1.5.5.7.3.2"
PRIV_REGEX_DEFAULT = r"(CN=Administrator|CN=krbtgt|Domain Admins|Enterprise Admins|UPN=.*admin@|svc-.*-admin)"

def openssl_dump(cert_path: Path) -> str:
    for args in (
        ["openssl", "x509", "-in", str(cert_path), "-text", "-noout"],
        ["openssl", "x509", "-in", str(cert_path), "-inform", "der", "-text", "-noout"],
    ):
        try:
            out = subprocess.check_output(args, stderr=subprocess.DEVNULL, text=True)
            if out.strip():
                return out
        except subprocess.CalledProcessError:
            pass
    return ""

def collect_files(paths):
    exts = {".cer", ".crt", ".pem", ".der"}
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for f in p.rglob("*"):
                if f.suffix.lower() in exts:
                    yield f
        else:
            yield p

def load_oids(path):
    if not path: return set()
    with open(path, "r", encoding="utf-8") as fh:
        return {line.strip() for line in fh if line.strip() and not line.startswith("#")}

def grab_block(text: str, start_marker: str, span: int = 12) -> str:
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if start_marker in ln:
            jmax = min(i+span+1, len(lines))
            return "\n".join(lines[i:jmax])
    return ""

def analyze_cert(text, priv_regex, danger_oids, evidence=False):
    res = {
        "ESC1_suspected": False, "ESC3": False, "ESC6": False, "ESC9": False,
        "ESC10_suspected": False, "ESC13": [], "ESC15": False,
        "subject": "", "policy_oids_found": [], "notes": []
    }
    ev = {}
    for line in text.splitlines():
        if line.strip().startswith("Subject:"):
            res["subject"] = line.strip()
            if evidence: ev["subject"] = line.strip()
            break

    has_upn = (OID_UPN in text)
    has_request_agent = (OID_REQUEST_AGENT in text)
    has_eku = ("Extended Key Usage" in text)
    has_app_policies = (OID_APP_POLICIES in text)
    has_clientauth_anywhere = (OID_CLIENTAUTH in text)

    san_block = grab_block(text, "Subject Alternative Name", span=6)
    eku_block = grab_block(text, "Extended Key Usage", span=4)
    pol_block = grab_block(text, "Certificate Policies", span=12)
    app_pol_block = grab_block(text, OID_APP_POLICIES, span=4)

    if evidence:
        if san_block: ev["san_block"] = san_block
        if eku_block: ev["eku_block"] = eku_block
        if pol_block: ev["policies_block"] = pol_block
        if app_pol_block: ev["app_policies_block"] = app_pol_block

    policy_oids = sorted(set(re.findall(r"(\d+(?:\.\d+)+)", pol_block)))
    res["policy_oids_found"] = policy_oids
    priv_hit = re.search(priv_regex, text, flags=re.IGNORECASE) is not None

    if has_request_agent:
        res["ESC3"] = True; res["notes"].append("ESC3: Request Agent EKU present.")
    if has_upn:
        res["ESC6"] = True; res["notes"].append("ESC6: UPN SAN present.")
    if not has_eku:
        res["ESC9"] = True; res["notes"].append("ESC9: No EKU present (implicitly any purpose).")
    if priv_hit:
        res["ESC10_suspected"] = True; res["notes"].append("ESC10?: Subject/SAN matches privileged pattern.")
    if has_upn and priv_hit:
        res["ESC1_suspected"] = True; res["notes"].append("ESC1?: Privileged UPN present; enrollee-supplied SAN likely.")
    if policy_oids:
        risky = [oid for oid in policy_oids if oid in danger_oids]
        if risky:
            res["ESC13"] = risky; res["notes"].append("ESC13: Dangerous policy OIDs present: " + ", ".join(risky))
    if has_app_policies and has_clientauth_anywhere:
        res["ESC15"] = True; res["notes"].append("ESC15: Application Policies present with clientAuth.")

    if evidence: res["evidence"] = ev
    return res

def render_html(results, outfile):
    css = """
body{font-family:Inter,Segoe UI,Arial,sans-serif;margin:24px;color:#0f172a;background:#ffffff}
h1{font-size:20px;margin:0 0 12px}
.card{border:1px solid #e2e8f0;border-radius:12px;margin:16px 0;padding:16px}
.path{color:#475569;font-size:12px;margin-bottom:8px}
.flags{margin:8px 0 12px}
.flag{display:inline-block;background:#eef2ff;color:#3730a3;border:1px solid #c7d2fe;border-radius:999px;padding:4px 10px;margin:2px;font-size:12px}
.kv{margin:4px 0}
pre{background:#0b1020;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto}
.note{color:#334155;font-size:13px;margin:6px 0}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#f1f5f9;color:#0f172a;border:1px solid #e2e8f0;font-size:12px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
"""
    def flags_spans(flaglist):
        if not flaglist: return ""
        return "".join(f'<span class="flag">{escape(f)}</span>' for f in flaglist)

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(f"<!doctype html><html><head><meta charset='utf-8'><title>ESC Check Report</title><style>{css}</style></head><body>")
        f.write('<div class="header"><h1>AD CS ESC Indicators Report</h1><span class="badge">Generated by esc_check.py</span></div>')
        for path, res in results.items():
            f.write('<div class="card">')
            f.write(f'<div class="path">{escape(path)}</div>')
            if "error" in res:
                f.write(f'<div class="note"><b>Error:</b> {escape(res["error"])}</div></div>')
                continue

            subj = res.get("subject","")
            if subj: f.write(f'<div class="kv"><strong>Subject:</strong> {escape(subj.replace("Subject: ",""))}</div>')

            pols = res.get("policy_oids_found",[])
            if pols: f.write(f'<div class="kv"><strong>Policy OIDs:</strong> {escape(", ".join(pols))}</div>')

            flags = []
            for k in ["ESC1_suspected","ESC3","ESC6","ESC9","ESC10_suspected","ESC15"]:
                if res.get(k): flags.append(k)
            if res.get("ESC13"): flags.append("ESC13(" + ",".join(res["ESC13"]) + ")")
            if flags:
                f.write('<div class="flags">' + flags_spans(flags) + '</div>')

            for n in res.get("notes", []):
                f.write(f'<div class="note">{escape(n)}</div>')

            ev = res.get("evidence", {})
            def block(title, key):
                content = ev.get(key, "")
                if content:
                    f.write(f'<div class="kv"><strong>{escape(title)}</strong></div>')
                    f.write(f'<pre>{escape(content)}</pre>')

            block("Subject", "subject")
            block("Subject Alternative Name", "san_block")
            block("Extended Key Usage", "eku_block")
            block("Certificate Policies", "policies_block")
            block(f"Application Policies ({OID_APP_POLICIES})", "app_policies_block")

            f.write("</div>")
        f.write("</body></html>")

def main():
    ap = argparse.ArgumentParser(description="Scan certs for AD CS ESC indicators (1-3,6,9,10,13,15).")
    ap.add_argument("paths", nargs="+", help="Cert file(s) or directory(ies).")
    ap.add_argument("--danger-oids", default="", help="File with one OID per line to flag for ESC13.")
    ap.add_argument("--priv-pattern", default=PRIV_REGEX_DEFAULT, help="Regex for privileged-looking identities.")
    ap.add_argument("--json", action="store_true", help="Output JSON.")
    ap.add_argument("--evidence", action="store_true", help="Include exact evidence blocks.")
    ap.add_argument("--evidence-html", metavar="OUT.html", help="Write an HTML report with evidence.")
    args = ap.parse_args()

    danger_oids = load_oids(args.danger_oids)
    results = {}

    for f in collect_files(args.paths):
        dump = openssl_dump(f)
        if not dump:
            results[str(f)] = {"error": "Unreadable certificate (PEM/DER)"}
            continue
        results[str(f)] = analyze_cert(dump, args.priv_pattern, danger_oids, evidence=(args.evidence or args.evidence_html))

    if args.json and not args.evidence_html:
        print(json.dumps(results, indent=2))
    else:
        for path, res in results.items():
            print(f"\n[{path}]")
            if "error" in res:
                print(f"  ERROR: {res['error']}")
                continue
            print(f"  Subject: {res.get('subject','').strip()}")
            if res.get("policy_oids_found"):
                print("  Policy OIDs:", ", ".join(res["policy_oids_found"]))
            flags = []
            for k in ["ESC1_suspected","ESC3","ESC6","ESC9","ESC10_suspected","ESC15"]:
                if res.get(k): flags.append(k)
            if res.get("ESC13"):
                flags.append("ESC13(" + ",".join(res["ESC13"]) + ")")
            print("  Flags:", ", ".join(flags) if flags else "None")
            for n in res.get("notes", []):
                print("   -", n)
            if args.evidence:
                ev = res.get("evidence", {})
                if ev:
                    print("  Evidence:")
                    for k in ["subject","san_block","eku_block","policies_block","app_policies_block"]:
                        if ev.get(k):
                            print(f"    [{k}]")
                            for line in ev[k].splitlines():
                                print("      " + line)

    if args.evidence_html:
        render_html(results, args.evidence_html)
        print(f"\nHTML report written to: {args.evidence_html}")

if __name__ == "__main__":
    main()
