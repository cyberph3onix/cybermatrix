"""Compliance audit, Module 6: reporter provenance by EIP-712 signature (M6-3). Offline, fake chain."""
from eth_account import Account
from eth_account.messages import encode_typed_data

from tests.test_api import assess, chain, client  # noqa: F401  (fixtures)

USER = Account.create()   # throwaway key made for the test, never funded
OTHER = Account.create()


def _sign(acct, data):
    return acct.sign_message(encode_typed_data(full_message=data)).signature.to_0x_hex()


def test_user_signature_is_verified_stored_and_shown(client):  # noqa: F811
    rid = assess(client)
    a = client.get(f"/reports/{rid}/attestations").json()
    data = a["typed_data"]
    assert data["primaryType"] == "ReportAttestation" and data["message"]["reportHash"] == a["report_hash"]
    assert data["domain"]["chainId"] == 11155111 and data["domain"]["verifyingContract"]
    assert a["attestations"] == []
    r = client.post(f"/reports/{rid}/attestations", json={"signer": USER.address, "signature": _sign(USER, data)})
    assert r.status_code == 200, r.text
    [att] = r.json()["attestations"]
    assert att["signer"] == USER.address and att["report_hash"] == a["report_hash"]
    # a second, different signer is a second attestation; the same signer again is not duplicated
    client.post(f"/reports/{rid}/attestations", json={"signer": OTHER.address, "signature": _sign(OTHER, data)})
    client.post(f"/reports/{rid}/attestations", json={"signer": USER.address, "signature": _sign(USER, data)})
    signers = [x["signer"] for x in client.get(f"/reports/{rid}/attestations").json()["attestations"]]
    assert sorted(signers) == sorted([USER.address, OTHER.address])


def test_forged_or_mismatched_signatures_are_rejected(client):  # noqa: F811
    rid, other_rid = assess(client), assess(client)
    data = client.get(f"/reports/{rid}/attestations").json()["typed_data"]
    other = client.get(f"/reports/{other_rid}/attestations").json()["typed_data"]
    # signed by OTHER but claimed as USER
    assert client.post(f"/reports/{rid}/attestations",
                       json={"signer": USER.address, "signature": _sign(OTHER, data)}).status_code == 422
    # a valid signature over a different report's hash does not attach here
    assert client.post(f"/reports/{rid}/attestations",
                       json={"signer": USER.address, "signature": _sign(USER, other)}).status_code == 422
    assert client.post(f"/reports/{rid}/attestations",
                       json={"signer": USER.address, "signature": "0x" + "00" * 65}).status_code == 422
    assert client.get(f"/reports/{rid}/attestations").json()["attestations"] == []


def test_incident_summary_is_redacted_committed_and_old_hashes_unchanged(client):  # noqa: F811
    import json

    from app.schemas import AssessmentReport, report_hash
    from app.store import hash_bytes
    from tests.test_chain import EXPECTED, FIXTURE
    # 1. a report from before the field existed re-hashes exactly as registered on Sepolia
    old = AssessmentReport.model_validate(json.loads(FIXTURE.read_text()))
    assert old.incident_summary is None and report_hash(old) == EXPECTED
    # 2. a user-written summary is masked, stored in the report and covered by its hash
    rid = assess(client, incident_summary="Got this by SMS from +91 98765 43210, I entered my card on the page.")
    raw = client.get(f"/reports/{rid}").content
    rep = AssessmentReport.model_validate_json(raw)
    assert rep.incident_summary and "98765" not in rep.incident_summary and "entered my card" in rep.incident_summary
    assert hash_bytes(raw) == report_hash(rep)
    # 3. without a summary the key is absent from the stored bytes
    assert b"incident_summary" not in client.get(f"/reports/{assess(client)}").content


def test_evidence_manifest_hashes_each_item_reproducibly(client):  # noqa: F811
    import hashlib

    import rfc8785

    from app.store import hash_bytes
    rid = assess(client)
    raw = client.get(f"/reports/{rid}").content
    m = client.get(f"/reports/{rid}/evidence").json()
    assert m["report_hash"] == hash_bytes(raw)
    rep = __import__("json").loads(raw)
    items = [(f["check_id"], i, e) for f in rep["findings"] + rep["security_posture"] for i, e in enumerate(f["evidence"])]
    assert len(m["evidence"]) == len(items) > 0
    for ref, (cid, i, e) in zip(m["evidence"], items, strict=True):
        assert (ref["check_id"], ref["index"]) == (cid, i)
        assert ref["sha256"] == hashlib.sha256(rfc8785.dumps(e)).hexdigest()
