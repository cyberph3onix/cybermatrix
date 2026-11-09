"""Tests for verify/verify.py.

Unit tests need only rfc8785 + eth-hash. The end-to-end tests need `anvil` and `forge` on PATH
(or in ~/.foundry/bin) and are skipped otherwise.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verify" / "verify.py"
CONTRACTS = ROOT / "contracts"
FIXTURE = ROOT / "backend" / "tests" / "fixtures" / "sample_report.json"
EXPECTED = "0xe8db935c3a232b5389c14869c1d0ace58d0f38c6231d1ecff0fecdceb2ad91d3"

# anvil's deterministic dev accounts 0 (deployer/validator) and 1 (relayer)
DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
RELAYER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

sys.path.insert(0, str(ROOT / "verify"))
import verify  # noqa: E402


def _one_char_changed(tmp_path: Path) -> Path:
    text = FIXTURE.read_text()
    assert '"score": 63' in text
    mutated = tmp_path / "tampered.json"
    mutated.write_text(text.replace('"score": 63', '"score": 64', 1))
    return mutated


# ---------- unit ----------


def test_fixture_hash_matches_expected() -> None:
    assert verify.compute_hash(verify.load_report(FIXTURE)) == EXPECTED


def test_hash_ignores_formatting() -> None:
    # JCS canonicalisation: whitespace and key order in the file don't matter.
    obj = verify.load_report(FIXTURE)
    reordered = json.loads(json.dumps(dict(reversed(list(obj.items())))))
    assert verify.compute_hash(reordered) == EXPECTED


def test_one_char_change_changes_hash(tmp_path: Path) -> None:
    assert verify.compute_hash(verify.load_report(_one_char_changed(tmp_path))) != EXPECTED
    obj = verify.load_report(FIXTURE)
    obj["subject"] = obj["subject"].replace("sbi", "sbj", 1)
    assert verify.compute_hash(obj) != EXPECTED


def test_bad_file_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    rc = verify.main(["--report", str(bad), "--rpc", "http://127.0.0.1:1", "--address", "0x" + "00" * 20])
    assert rc == verify.EXIT_ERROR


# ---------- end-to-end on anvil ----------


def _tool(name: str) -> str | None:
    return shutil.which(name) or (str(p) if (p := Path.home() / ".foundry" / "bin" / name).exists() else None)


ANVIL, FORGE = _tool("anvil"), _tool("forge")
needs_foundry = pytest.mark.skipif(not (ANVIL and FORGE), reason="anvil/forge not installed")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def chain():
    from web3 import Web3

    subprocess.run([FORGE, "build", "--silent"], cwd=CONTRACTS, check=True)
    artifact = json.loads((CONTRACTS / "out" / "ThreatRegistry.sol" / "ThreatRegistry.json").read_text())

    port = _free_port()
    proc = subprocess.Popen([ANVIL, "--port", str(port), "--silent"], stdout=subprocess.DEVNULL)
    rpc = f"http://127.0.0.1:{port}"
    w3 = Web3(Web3.HTTPProvider(rpc))
    for _ in range(100):
        if w3.is_connected():
            break
        time.sleep(0.05)
    else:
        proc.kill()
        pytest.fail("anvil did not start")

    def send(key: str, tx: dict) -> dict:
        acct = w3.eth.account.from_key(key)
        tx = {
            **tx,
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address),
            "chainId": w3.eth.chain_id,
        }
        tx.setdefault("gas", w3.eth.estimate_gas(tx))  # fees come from build_transaction (EIP-1559)
        signed = acct.sign_transaction(tx)
        receipt = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed.raw_transaction))
        assert receipt["status"] == 1
        return receipt

    Factory = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"]["object"])
    address = send(
        DEPLOYER_KEY, Factory.constructor().build_transaction({"from": w3.eth.account.from_key(DEPLOYER_KEY).address})
    )["contractAddress"]
    reg = w3.eth.contract(address=address, abi=artifact["abi"])

    relayer = w3.eth.account.from_key(RELAYER_KEY).address
    send(
        RELAYER_KEY,
        reg.functions.submitReport(bytes.fromhex(EXPECTED[2:]), b"\x00" * 32).build_transaction({"from": relayer}),
    )

    yield {"rpc": rpc, "address": address, "w3": w3, "reg": reg, "send": send}
    proc.terminate()
    proc.wait(timeout=5)


def _run(report: Path, chain: dict, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(VERIFY),
            "--report",
            str(report),
            "--rpc",
            chain["rpc"],
            "--address",
            chain["address"],
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": ""},
    )


@needs_foundry
def test_e2e_match(chain: dict) -> None:
    p = _run(FIXTURE, chain)
    assert p.returncode == 0, p.stderr
    assert p.stdout.startswith("MATCH")
    assert EXPECTED in p.stdout
    assert "status        : submitted" in p.stdout
    assert "tx            : 0x" in p.stdout


@needs_foundry
def test_e2e_match_json(chain: dict) -> None:
    p = _run(FIXTURE, chain, "--json")
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout)
    assert out["result"] == "MATCH"
    assert out["onchain_hash"] == EXPECTED
    assert out["onchain_id"] == 1
    assert out["created_at"].endswith("Z")
    assert "explorer_url" not in out  # anvil has no explorer


@needs_foundry
def test_e2e_one_char_change_is_mismatch(chain: dict, tmp_path: Path) -> None:
    p = _run(_one_char_changed(tmp_path), chain)
    assert p.returncode == 1, p.stderr
    assert p.stdout.startswith("MISMATCH")
    assert "not registered" in p.stdout


@needs_foundry
def test_e2e_status_change_visible(chain: dict) -> None:
    w3, reg, send = chain["w3"], chain["reg"], chain["send"]
    deployer = w3.eth.account.from_key(DEPLOYER_KEY).address
    send(DEPLOYER_KEY, reg.functions.addValidator(deployer).build_transaction({"from": deployer}))
    send(DEPLOYER_KEY, reg.functions.setStatus(1, 2).build_transaction({"from": deployer}))
    out = json.loads(_run(FIXTURE, chain, "--json").stdout)
    assert out["result"] == "MATCH"
    assert out["status"] == "validated"


@needs_foundry
def test_e2e_bad_rpc_exits_2(chain: dict) -> None:
    p = subprocess.run(
        [
            sys.executable,
            str(VERIFY),
            "--report",
            str(FIXTURE),
            "--rpc",
            f"http://127.0.0.1:{_free_port()}",
            "--address",
            chain["address"],
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p.returncode == 2
    assert "ERROR" in p.stderr
