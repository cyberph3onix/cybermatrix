"""ChainClient against a local anvil node (skipped if Foundry isn't installed)."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import pytest_asyncio

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.registry import chain as chain_mod  # noqa: E402
from app.registry.chain import ChainClient, ChainError  # noqa: E402
from app.schemas import AssessmentReport, RegistryStatus, report_hash  # noqa: E402

CONTRACTS = BACKEND.parent / "contracts"
ARTIFACT = CONTRACTS / "out" / "ThreatRegistry.sol" / "ThreatRegistry.json"
FIXTURE = BACKEND / "tests" / "fixtures" / "sample_report.json"
EXPECTED = "0xe8db935c3a232b5389c14869c1d0ace58d0f38c6231d1ecff0fecdceb2ad91d3"

# anvil dev accounts: 0 = deployer/owner/validator, 1 = relayer (submit only)
DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
RELAYER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
DISPUTER_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"  # anvil account 2


def _tool(name: str) -> str | None:
    return shutil.which(name) or (str(p) if (p := Path.home() / ".foundry" / "bin" / name).exists() else None)


ANVIL, FORGE = _tool("anvil"), _tool("forge")
pytestmark = pytest.mark.skipif(not (ANVIL and FORGE), reason="anvil/forge not installed")


def _report(**overrides) -> AssessmentReport:
    data = json.loads(FIXTURE.read_text())
    data.update(overrides)
    return AssessmentReport.model_validate(data)


@pytest.fixture(scope="module")
def node():
    from web3 import Web3

    subprocess.run([FORGE, "build", "--silent"], cwd=CONTRACTS, check=True)
    artifact = json.loads(ARTIFACT.read_text())
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
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

    deployer = w3.eth.account.from_key(DEPLOYER_KEY)

    def send(tx: dict) -> dict:
        tx = {**tx, "from": deployer.address, "nonce": w3.eth.get_transaction_count(deployer.address)}
        signed = deployer.sign_transaction(tx)
        r = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed.raw_transaction))
        assert r["status"] == 1
        return r

    factory = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"]["object"])
    address = send(factory.constructor().build_transaction({"from": deployer.address}))["contractAddress"]
    reg = w3.eth.contract(address=address, abi=artifact["abi"])
    send(reg.functions.addValidator(deployer.address).build_transaction({"from": deployer.address}))
    send(reg.functions.setDisputeBond(10**15).build_transaction({"from": deployer.address}))
    disputer = w3.eth.account.from_key(DISPUTER_KEY)

    def dispute_from_wallet(calldata: str, value: int) -> dict:
        """What the browser wallet does with /dispute-reason's answer."""
        tx = {"to": address, "data": calldata, "value": value, "from": disputer.address, "chainId": 31337,
              "nonce": w3.eth.get_transaction_count(disputer.address), "gas": 200_000, "gasPrice": w3.eth.gas_price}
        return w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(disputer.sign_transaction(tx).raw_transaction))

    def set_status(onchain_id: int, status: int) -> None:
        send(reg.functions.setStatus(onchain_id, status).build_transaction({"from": deployer.address}))

    yield {"rpc": rpc, "address": address, "set_status": set_status, "dispute": dispute_from_wallet,
           "disputer": disputer.address}
    proc.terminate()
    proc.wait(timeout=5)


@pytest_asyncio.fixture
async def client(node):
    async with ChainClient(node["rpc"], node["address"], RELAYER_KEY, receipt_timeout_s=30) as c:
        yield c


def test_committed_abi_matches_build_output(node) -> None:
    assert chain_mod.load_abi() == json.loads(ARTIFACT.read_text())["abi"], "run contracts/script/export_abi.sh"


@pytest.mark.asyncio
async def test_repr_hides_key(client: ChainClient) -> None:
    assert RELAYER_KEY[2:] not in repr(client)
    assert RELAYER_KEY[2:] not in repr(client.__dict__.get("_account"))


@pytest.mark.asyncio
async def test_submit_get_verify_roundtrip(client: ChainClient) -> None:
    report = _report()
    assert report_hash(report) == EXPECTED

    rec = await client.submit_report(report)
    assert rec.report_hash == EXPECTED
    assert rec.onchain_id == 1
    assert rec.tx_hash and rec.tx_hash.startswith("0x")
    assert rec.reporter_address == client.relayer_address
    assert rec.chain_id == 31337
    assert rec.status == RegistryStatus.SUBMITTED.value

    onchain = await client.get_report(rec.onchain_id)
    assert onchain.report_hash == EXPECTED
    assert onchain.status == RegistryStatus.SUBMITTED

    v = await client.verify(report, rec.tx_hash)
    assert v.match and v.onchain_hash == EXPECTED
    assert v.onchain_status == RegistryStatus.SUBMITTED.value
    assert v.explorer_url is None  # anvil

    tampered = _report(score=64)
    v2 = await client.verify(tampered)
    assert not v2.match and v2.onchain_hash is None


@pytest.mark.asyncio
async def test_submit_is_idempotent(client: ChainClient) -> None:
    rec = await client.submit_report(_report())  # already registered above
    assert rec.onchain_id == 1
    assert rec.tx_hash is None


@pytest.mark.asyncio
async def test_supersede(client: ChainClient) -> None:
    parent = _report(salt="cd" * 32)
    p = await client.submit_report(parent)
    child = await client.submit_report(_report(salt="ef" * 32), parent_hash=p.report_hash)
    assert (await client.get_report(p.onchain_id)).status == RegistryStatus.SUPERSEDED
    assert (await client.get_report(child.onchain_id)).parent_hash == p.report_hash

    with pytest.raises(ChainError) as e:
        await client.submit_report(_report(salt="12" * 32), parent_hash=p.report_hash)
    assert e.value.reason == "ParentAlreadySuperseded"


@pytest.mark.asyncio
async def test_rejected_parent_cannot_be_superseded(client: ChainClient, node) -> None:
    p = await client.submit_report(_report(salt="34" * 32))
    node["set_status"](p.onchain_id, 3)  # validator rejects
    assert (await client.get_report(p.onchain_id)).status == RegistryStatus.REJECTED
    with pytest.raises(ChainError) as e:
        await client.submit_report(_report(salt="56" * 32), parent_hash=p.report_hash)
    assert e.value.reason == "ParentRejected"


@pytest.mark.asyncio
async def test_unknown_parent_reverts(client: ChainClient) -> None:
    with pytest.raises(ChainError) as e:
        await client.submit_report(_report(salt="78" * 32), parent_hash="0x" + "99" * 32)
    assert e.value.reason == "ParentNotFound"


@pytest.mark.asyncio
async def test_get_unknown_id_reverts(client: ChainClient) -> None:
    with pytest.raises(ChainError) as e:
        await client.get_report(999)
    assert e.value.reason == "ReportNotFound"


@pytest.mark.asyncio
async def test_concurrent_submits_get_distinct_nonces(client: ChainClient) -> None:
    import asyncio

    recs = await asyncio.gather(*(client.submit_report(_report(salt=f"{i:02x}" * 32)) for i in range(0xA0, 0xA4)))
    assert len({r.onchain_id for r in recs}) == 4


@pytest.mark.asyncio
async def test_read_only_client_cannot_submit(node) -> None:
    async with ChainClient(node["rpc"], node["address"]) as ro:
        with pytest.raises(ChainError) as e:
            await ro.submit_report(_report(salt="ab" * 31 + "cd"))
    assert e.value.reason == "NotConfigured"


@pytest.mark.asyncio
async def test_bonded_dispute_from_user_wallet(client: ChainClient, node) -> None:
    rec = await client.submit_report(_report(salt="77" * 32))
    assert await client.dispute_bond() == 10**15
    assert await client.get_dispute(rec.onchain_id) is None
    calldata = client.dispute_calldata(rec.onchain_id, "0x" + "42" * 32)
    assert node["dispute"](calldata, 0)["status"] == 0  # no bond: WrongBond revert
    assert node["dispute"](calldata, 10**15)["status"] == 1
    assert await client.get_dispute(rec.onchain_id) == (node["disputer"], 10**15)
    assert (await client.get_report(rec.onchain_id)).status == RegistryStatus.DISPUTED
