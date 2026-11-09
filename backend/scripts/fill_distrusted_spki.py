"""One-off: complete data/distrusted_cas.json from crt.sh. Only public certificates are handled; nothing is signed.

What it does, for each ORIGINAL entry (relation "original"):
  1. Download the cert DER from crt.sh by SHA-256 and CHECK sha256(DER) == the listed fingerprint.
  2. Compute spki_sha256 and save the PEM as a public test fixture in tests/fixtures/certs/emudhra/.
  3. Search crt.sh by SPKI for every other certificate carrying the same public key. Each one is downloaded, its
     SPKI re-checked, and added as an entry with relation "cross_sign" (different issuer) or "reissue" (same
     issuer as the original), plus a PEM fixture.
Then it resolves the removed root(s) by subject CN.

Provenance on every entry: crt_sh_id, derived_from (the original intermediate's name), fetched_at (UTC time the
DER was downloaded and its fingerprint verified), relation.

Exit status: 0 only if every upstream call succeeded. Any upstream error that survives the retries (a crt.sh 502,
a fingerprint mismatch, an unparseable response) makes the run exit 1, so a partial run can never look green.

Usage:
  uv run python scripts/fill_distrusted_spki.py                       # full run
  uv run python scripts/fill_distrusted_spki.py --only "EM EV TLS CA - G3B"   # SPKI search for one original
  uv run python scripts/fill_distrusted_spki.py --provenance          # (re)verify every entry, fill provenance
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.fetch.api_client import ApiClient, ApiUnavailable  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "distrusted_cas.json"
PEM_DIR = ROOT / "tests" / "fixtures" / "certs" / "emudhra"
CRT = "https://crt.sh/"
ID_RE = re.compile(r"crt\.sh ID</TH>\s*<TD[^>]*><A href=\"\?id=(\d+)\"", re.I)
ENTRY_KEYS = ("incident", "name", "org", "type", "relation", "derived_from", "serial", "subject", "issuer",
              "cert_sha256", "spki_sha256", "crt_sh_id", "fetched_at")


class Upstream(Exception):
    """An upstream failure that survived all retries."""


MAX_ATTEMPTS = 12


async def retry(what: str, fn, *a, **kw):
    """Retry with exponential backoff (2 s doubling, capped at 60 s) until the call succeeds or attempts run out."""
    delay = 2.0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return await fn(*a, **kw)
        except (ApiUnavailable, ValueError) as e:
            if attempt == MAX_ATTEMPTS:
                raise Upstream(f"{what}: {e} (gave up after {MAX_ATTEMPTS} attempts)") from None
            print(f"  {what}: {e}; retry {attempt}/{MAX_ATTEMPTS - 1} in {delay:.0f}s")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60.0)


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def spki_sha256(cert: x509.Certificate) -> str:
    der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest().upper()


def cert_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest().upper()


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def cn(name: x509.Name) -> str:
    a = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(a[0].value) if a else name.rfc4514_string()


async def download(api: ApiClient, ident: str | int) -> x509.Certificate:
    async def once() -> x509.Certificate:
        pem = await api.get_text(CRT, params={"d": str(ident)})
        return x509.load_pem_x509_certificate(pem.encode())  # an HTML error page raises ValueError -> retried
    return await retry(f"download {ident}", once)


async def crtsh_id_for(api: ApiClient, sha256: str) -> int:
    async def once() -> int:
        html = await api.get_text(CRT, params={"sha256": sha256})
        m = ID_RE.search(html)
        if not m:
            raise ValueError("no crt.sh ID on certificate page")
        return int(m.group(1))
    return await retry(f"id lookup {sha256[:12]}", once)


async def spki_search(api: ApiClient, spki: str) -> list[dict]:
    async def once() -> list[dict]:
        rows = await api.get_json(CRT, params={"spkisha256": spki.lower(), "output": "json"})
        if not isinstance(rows, list):
            raise ValueError("unexpected SPKI search response")
        return rows
    return await retry(f"SPKI search {spki[:12]}", once)


def fixture_name(e: dict) -> str:
    if e["relation"] == "original":
        return f"{slug(e['name'])}.pem"
    tag = "xsign" if e["relation"] == "cross_sign" else "reissue"
    return f"{slug(e['derived_from'])}__{tag}_{e['crt_sh_id']}.pem"


def same_key_entry(orig: dict, cert: x509.Certificate, crt_id: int, fetched_at: str) -> dict:
    reissue = cert.issuer.rfc4514_string() == orig["issuer"]
    by = cert.issuer.rfc4514_string()
    return {
        "incident": orig["incident"],
        "name": f"{orig['name']} ({'re-issued' if reissue else 'cross-signed'} by {by})",
        "org": orig["org"], "type": orig["type"],
        "relation": "reissue" if reissue else "cross_sign", "derived_from": orig["name"],
        "serial": format(cert.serial_number, "x"), "subject": cert.subject.rfc4514_string(), "issuer": by,
        "cert_sha256": cert_sha256(cert), "spki_sha256": spki_sha256(cert),
        "crt_sh_id": crt_id, "fetched_at": fetched_at,
    }


def normalise(e: dict) -> dict:
    """Migrate the old shape (cross_sign_of / crtsh_id) and order keys."""
    if "cross_sign_of" in e:
        e["derived_from"] = e.pop("cross_sign_of")
    if "crtsh_id" in e:
        e["crt_sh_id"] = e.pop("crtsh_id")
    e.setdefault("derived_from", e["name"])
    e.setdefault("relation", "original" if e["derived_from"] == e["name"] else "cross_sign")
    return {k: e[k] for k in ENTRY_KEYS if k in e} | {k: v for k, v in e.items() if k not in ENTRY_KEYS}


def save_pem(e: dict, cert: x509.Certificate) -> None:
    (PEM_DIR / fixture_name(e)).write_bytes(cert.public_bytes(Encoding.PEM))


async def verify_entry(api: ApiClient, e: dict, originals: dict[str, dict]) -> None:
    """Re-download by crt.sh ID (looked up if missing), verify the fingerprint, and fill provenance."""
    if not e.get("crt_sh_id"):
        e["crt_sh_id"] = await crtsh_id_for(api, e["cert_sha256"])
    cert = await download(api, e["crt_sh_id"])
    if cert_sha256(cert) != e["cert_sha256"].upper():
        raise Upstream(f"{e['name']}: crt.sh id {e['crt_sh_id']} has fingerprint {cert_sha256(cert)}, "
                       f"expected {e['cert_sha256']}")
    e["fetched_at"] = now_iso()
    e["spki_sha256"] = spki_sha256(cert)
    e["subject"], e["issuer"] = cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
    if e["relation"] != "original":
        orig = originals[e["derived_from"]]
        if e["spki_sha256"] != orig["spki_sha256"]:
            raise Upstream(f"{e['name']}: SPKI differs from {orig['name']}")
        fresh = same_key_entry(orig, cert, e["crt_sh_id"], e["fetched_at"])
        old = PEM_DIR / fixture_name(e)
        e.update({k: fresh[k] for k in ("name", "relation")})
        if old.name != fixture_name(e) and old.exists():
            old.unlink()
    save_pem(e, cert)
    print(f"  ok {e['relation']:<10} id {e['crt_sh_id']}  {e['name']}")


async def search_same_key(api: ApiClient, orig: dict, doc: dict, known: set[str]) -> int:
    print(f"{orig['name']}: SPKI search {orig['spki_sha256'][:16]}…")
    rows = await spki_search(api, orig["spki_sha256"])
    added = 0
    for row in rows:
        cert = await download(api, row["id"])
        h = cert_sha256(cert)
        if spki_sha256(cert) != orig["spki_sha256"]:
            raise Upstream(f"{orig['name']}: crt.sh id {row['id']} returned by SPKI search has a different SPKI")
        if h == orig["cert_sha256"].upper():
            orig.setdefault("crt_sh_id", row["id"])
            continue
        if h in known:
            continue
        e = same_key_entry(orig, cert, row["id"], now_iso())
        doc["entries"].append(e)
        save_pem(e, cert)
        known.add(h)
        added += 1
        print(f"  + {e['relation']} {h[:16]}… id {row['id']} issued by {cn(cert.issuer)}")
    print(f"  {len(rows)} cert(s) with this key, {added} new")
    return added


async def resolve_roots(api: ApiClient, doc: dict) -> None:
    for root in doc.get("removed_roots", []):
        print(f"removed root {root['name']}:")
        rows = await retry(f"CN search {root['name']}", api.get_json, CRT,
                           params={"CN": root["name"], "output": "json"})
        certs = [c for c in [await download(api, r["id"]) for r in rows] if cn(c.subject) == root["name"]]
        if not certs:
            raise Upstream(f"root {root['name']}: no certificate with that CN found")
        root["spki_sha256"] = sorted({spki_sha256(c) for c in certs})
        root["cert_sha256"] = sorted({cert_sha256(c) for c in certs})
        root["fetched_at"] = now_iso()
        for c in certs:
            (PEM_DIR / f"root_{slug(root['name'])}_{cert_sha256(c)[:12].lower()}.pem").write_bytes(
                c.public_bytes(Encoding.PEM))
        print(f"  {len(certs)} cert(s), {len(root['spki_sha256'])} key(s)")


async def main(argv: list[str]) -> int:
    global MAX_ATTEMPTS
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", action="append", help="limit the SPKI search to these original entry names")
    ap.add_argument("--provenance", action="store_true", help="re-verify every entry and fill provenance")
    ap.add_argument("--max-attempts", type=int, default=MAX_ATTEMPTS)
    args = ap.parse_args(argv)
    MAX_ATTEMPTS = args.max_attempts

    doc = json.loads(DATA.read_text())
    doc["entries"] = [normalise(e) for e in doc["entries"]]
    PEM_DIR.mkdir(parents=True, exist_ok=True)
    originals = {e["name"]: e for e in doc["entries"] if e["relation"] == "original"}
    if args.only and (missing := set(args.only) - originals.keys()):
        print(f"unknown original(s): {sorted(missing)}")
        return 2
    known = {e["cert_sha256"].upper() for e in doc["entries"]}
    problems: list[str] = []

    async with ApiClient(timeout=40) as api:
        targets = [originals[n] for n in args.only] if args.only else list(originals.values())
        if not args.provenance or args.only:
            for orig in targets:
                try:
                    if not args.only:  # full run: (re)verify the original first
                        await verify_entry(api, orig, originals)
                    await search_same_key(api, orig, doc, known)
                except Upstream as ex:
                    problems.append(str(ex))
        if args.provenance:
            print("provenance:")
            for e in doc["entries"]:
                try:
                    await verify_entry(api, e, originals)
                except Upstream as ex:
                    problems.append(str(ex))
        if not args.only and not args.provenance:
            try:
                await resolve_roots(api, doc)
            except Upstream as ex:
                problems.append(str(ex))

    doc["entries"] = [normalise(e) for e in doc["entries"]]
    DATA.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    n_orig = sum(e["relation"] == "original" for e in doc["entries"])
    print(f"\nwrote {DATA}: {len(doc['entries'])} entries ({n_orig} originals, "
          f"{len(doc['entries']) - n_orig} same-key certs)")
    if problems:
        print("FAILED, upstream errors:\n  " + "\n  ".join(problems))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
