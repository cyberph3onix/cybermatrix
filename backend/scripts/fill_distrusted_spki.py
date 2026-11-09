"""One-off: fill spki_sha256 in data/distrusted_cas.json from crt.sh and find cross-signed copies of the same keys.

For each entry: download the cert DER from crt.sh by SHA-256, CHECK that sha256(DER) equals the listed fingerprint,
compute the SPKI SHA-256, save the PEM as a public test fixture, then search crt.sh by SPKI for other certificates
carrying the same public key (cross-signs) and add them as entries with `cross_sign_of`. Also resolves the removed
root(s) by subject CN. Nothing is guessed: failed lookups are reported and left null.

Only public certificates are handled here. Nothing is ever signed.

Usage: uv run python scripts/fill_distrusted_spki.py
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.fetch.api_client import ApiClient, ApiUnavailable  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "distrusted_cas.json"
PEM_DIR = ROOT / "tests" / "fixtures" / "certs" / "emudhra"
CRT = "https://crt.sh/"


async def retry(fn, *a, **kw):
    delay = 2.0
    for attempt in range(5):
        try:
            return await fn(*a, **kw)
        except ApiUnavailable as e:
            if attempt == 4:
                raise
            print(f"  crt.sh: {e}; retrying in {delay:.0f}s")
            await asyncio.sleep(delay)
            delay *= 2


def spki_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def cert_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


async def download(api: ApiClient, ident: str) -> x509.Certificate:
    pem = await retry(api.get_text, CRT, params={"d": ident})
    return x509.load_pem_x509_certificate(pem.encode())


def summary(cert: x509.Certificate) -> dict:
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "serial": format(cert.serial_number, "x"), "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat()}


async def main() -> int:
    doc = json.loads(DATA.read_text())
    PEM_DIR.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    known = {e["cert_sha256"].upper() for e in doc["entries"]}
    new_entries: list[dict] = []
    async with ApiClient(timeout=40) as api:
        for e in [x for x in doc["entries"] if not x.get("cross_sign_of")]:
            print(f"{e['name']}:")
            try:
                cert = await download(api, e["cert_sha256"])
            except (ApiUnavailable, ValueError) as ex:
                problems.append(f"{e['name']}: download failed ({ex})")
                continue
            got = cert_sha256(cert).upper()
            if got != e["cert_sha256"].upper():
                problems.append(f"{e['name']}: fingerprint MISMATCH (crt.sh returned {got}); left unfilled")
                continue
            e["spki_sha256"] = spki_sha256(cert).upper()
            e.update({k: v for k, v in summary(cert).items() if k in ("subject", "issuer")})
            (PEM_DIR / f"{slug(e['name'])}.pem").write_bytes(cert.public_bytes(Encoding.PEM))
            print(f"  spki {e['spki_sha256'][:16]}…  issuer {e['issuer']}")
            try:
                rows = await retry(api.get_json, CRT, params={"spkisha256": e["spki_sha256"].lower(),
                                                              "output": "json"})
            except ApiUnavailable as ex:
                problems.append(f"{e['name']}: SPKI search failed ({ex})")
                continue
            for row in rows:
                try:
                    other = await download(api, str(row["id"]))
                except (ApiUnavailable, ValueError) as ex:
                    problems.append(f"{e['name']}: cross-sign crt.sh id {row['id']} download failed ({ex})")
                    continue
                h = cert_sha256(other).upper()
                if h in known or spki_sha256(other).upper() != e["spki_sha256"]:
                    continue
                known.add(h)
                s = summary(other)
                new_entries.append({
                    "incident": e["incident"], "name": f"{e['name']} (cross-signed by {other.issuer.rfc4514_string()})",
                    "org": e["org"], "type": e["type"], "serial": s["serial"], "cert_sha256": h,
                    "spki_sha256": e["spki_sha256"], "cross_sign_of": e["name"], "issuer": s["issuer"],
                    "subject": s["subject"], "crtsh_id": row["id"]})
                (PEM_DIR / f"{slug(e['name'])}__xsign_{row['id']}.pem").write_bytes(other.public_bytes(Encoding.PEM))
                print(f"  + cross-sign {h[:16]}… issued by {s['issuer']}")
        doc["entries"] += new_entries

        for root in doc.get("removed_roots", []):
            print(f"removed root {root['name']}:")
            try:
                rows = await retry(api.get_json, CRT, params={"CN": root["name"], "output": "json"})
            except ApiUnavailable as ex:
                problems.append(f"root {root['name']}: search failed ({ex})")
                continue
            certs = []
            for row in rows:
                try:
                    c = await download(api, str(row["id"]))
                except (ApiUnavailable, ValueError):
                    continue
                cn = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                if cn and cn[0].value == root["name"]:
                    certs.append(c)
            if not certs:
                problems.append(f"root {root['name']}: no certificate with that CN found")
                continue
            root["spki_sha256"] = sorted({spki_sha256(c).upper() for c in certs})
            root["cert_sha256"] = sorted({cert_sha256(c).upper() for c in certs})
            for c in certs:
                (PEM_DIR / f"root_{slug(root['name'])}_{cert_sha256(c)[:12]}.pem").write_bytes(
                    c.public_bytes(Encoding.PEM))
            print(f"  {len(certs)} cert(s), {len(root['spki_sha256'])} key(s)")

    DATA.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"\nwrote {DATA} ({len(new_entries)} cross-sign entries added)")
    if problems:
        print("PROBLEMS:\n  " + "\n  ".join(problems))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
