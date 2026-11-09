"""ThreatRegistry client: relayer submit + on-chain reads.

Only the report hash, parent hash, status, timestamps and reporter address touch the chain (CLAUDE.md rule 7).
The relayer key signs locally and is never logged, put in a repr, or sent anywhere.

The ABI in abi/ThreatRegistry.json is generated from the Foundry build output by
contracts/script/export_abi.sh. Do not hand-edit it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any, Self

from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_hash.auto import keccak
from web3 import AsyncHTTPProvider, AsyncWeb3
from web3.exceptions import ContractCustomError, ContractLogicError, TimeExhausted, Web3Exception
from web3.logs import DISCARD

from app.schemas import (
    AssessmentReport,
    RegistryRecord,
    RegistryStatus,
    VerificationResult,
    report_hash,
)

log = logging.getLogger(__name__)

ABI_PATH = Path(__file__).parent / "abi" / "ThreatRegistry.json"
ZERO_HASH = "0x" + "00" * 32
# Index order mirrors `enum Status` in ThreatRegistry.sol.
STATUS_BY_INDEX: tuple[RegistryStatus, ...] = (
    RegistryStatus.SUBMITTED,
    RegistryStatus.DISPUTED,
    RegistryStatus.VALIDATED,
    RegistryStatus.REJECTED,
    RegistryStatus.SUPERSEDED,
)
EXPLORERS: dict[int, str] = {1: "https://etherscan.io", 11155111: "https://sepolia.etherscan.io"}


class ChainError(Exception):
    """The contract rejected the call (custom error name in `.reason`), or the client is misconfigured."""

    def __init__(self, reason: str, detail: str | None = None) -> None:
        super().__init__(reason if detail is None else f"{reason}: {detail}")
        self.reason = reason


class ChainUnavailable(Exception):
    """RPC unreachable, timed out, or the transaction was not mined in time."""


@cache
def load_abi() -> list[dict[str, Any]]:
    return json.loads(ABI_PATH.read_text())


@cache
def _error_selectors() -> dict[str, str]:
    """4-byte selector (0x-hex) → custom error name, for decoding reverts."""
    out: dict[str, str] = {}
    for item in load_abi():
        if item.get("type") == "error":
            sig = f"{item['name']}({','.join(i['type'] for i in item['inputs'])})"
            out["0x" + keccak(sig.encode()).hex()[:8]] = item["name"]
    return out


def _decode_revert(e: Exception) -> ChainError:
    data = getattr(e, "data", None)
    if isinstance(data, str) and len(data) >= 10:
        name = _error_selectors().get(data[:10].lower())
        if name:
            return ChainError(name)
    return ChainError("Reverted", str(e))


def reporter_trusted(chain: Any, reporter: str | None) -> bool:
    """True if `reporter` is this server's relayer. submitReport is open to every address, so a hash on-chain only
    means a CyberMatrix report when our relayer put it there. Without a configured relayer we cannot tell."""
    ours = getattr(chain, "relayer_address", None)
    return ours is None or (reporter or "").lower() == ours.lower()


def _hex32(value: str | bytes) -> bytes:
    raw = bytes.fromhex(value.removeprefix("0x")) if isinstance(value, str) else value
    if len(raw) != 32:
        raise ValueError("expected a 32-byte hash")
    return raw


def _to_hex(b: bytes) -> str:
    return "0x" + bytes(b).hex()


class OnchainReport:
    __slots__ = ("created_at", "id", "parent_hash", "report_hash", "reporter", "status")

    def __init__(self, id: int, raw: tuple[bytes, bytes, str, int, int]) -> None:
        self.id = id
        self.report_hash = _to_hex(raw[0])
        self.parent_hash = _to_hex(raw[1])
        self.reporter: str = raw[2]
        self.created_at = datetime.fromtimestamp(raw[3], tz=UTC)
        self.status = STATUS_BY_INDEX[raw[4]]

    def __repr__(self) -> str:
        return f"OnchainReport(id={self.id}, hash={self.report_hash}, status={self.status})"


class ChainClient:
    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        relayer_private_key: str | None = None,
        *,
        receipt_timeout_s: int = 180,
    ) -> None:
        self._w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url, request_kwargs={"timeout": 15}))
        self.address = AsyncWeb3.to_checksum_address(contract_address)
        self._contract = self._w3.eth.contract(address=self.address, abi=load_abi())
        self._account: LocalAccount | None = Account.from_key(relayer_private_key) if relayer_private_key else None
        self._receipt_timeout_s = receipt_timeout_s
        self._send_lock = asyncio.Lock()  # serialises nonce allocation for the single relayer account
        self._chain_id: int | None = None

    @classmethod
    def from_env(cls) -> ChainClient:
        rpc, addr = os.environ.get("SEPOLIA_RPC_URL"), os.environ.get("REGISTRY_ADDRESS")
        if not rpc or not addr:
            raise ChainError("NotConfigured", "SEPOLIA_RPC_URL and REGISTRY_ADDRESS must be set")
        return cls(rpc, addr, os.environ.get("RELAYER_PRIVATE_KEY") or None)

    async def aclose(self) -> None:
        """Close the provider's HTTP session (call on app shutdown)."""
        await self._w3.provider.disconnect()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def __repr__(self) -> str:  # never include the key
        return f"ChainClient(address={self.address}, relayer={self.relayer_address})"

    @property
    def relayer_address(self) -> str | None:
        return self._account.address if self._account else None

    async def chain_id(self) -> int:
        if self._chain_id is None:
            self._chain_id = await self._call(self._w3.eth.chain_id)
        return self._chain_id

    async def explorer_url(self, tx_hash: str | None = None) -> str | None:
        base = EXPLORERS.get(await self.chain_id())
        if base is None:
            return None
        return f"{base}/tx/{tx_hash}" if tx_hash else f"{base}/address/{self.address}"

    # ---------- reads ----------

    async def id_of_hash(self, h: str | bytes) -> int:
        return await self._call(self._contract.functions.idOfHash(_hex32(h)).call())

    async def get_report(self, onchain_id: int) -> OnchainReport:
        raw = await self._call(self._contract.functions.getReport(onchain_id).call())
        return OnchainReport(onchain_id, tuple(raw))

    async def find_by_hash(self, h: str | bytes) -> OnchainReport | None:
        onchain_id = await self.id_of_hash(h)
        return await self.get_report(onchain_id) if onchain_id else None

    async def dispute_bond(self) -> int:
        return int(await self._call(self._contract.functions.disputeBond().call()))

    async def get_dispute(self, onchain_id: int) -> tuple[str, int] | None:
        """(disputer, bond_wei) of the open dispute, or None."""
        disputer, bond = await self._call(self._contract.functions.getDispute(onchain_id).call())
        return None if int(disputer, 16) == 0 else (disputer, int(bond))

    def dispute_calldata(self, onchain_id: int, reason_hash: str) -> str:
        """ABI-encoded disputeReport call. The user's wallet sends it (with the bond); the relayer never disputes."""
        return self._contract.encode_abi("disputeReport", args=[onchain_id, _hex32(reason_hash)])

    # ---------- writes ----------

    async def submit_report(self, report: AssessmentReport, parent_hash: str | None = None) -> RegistryRecord:
        """Commit `report` on-chain via the relayer. Idempotent: an already-registered hash is returned as-is."""
        h = report_hash(report)
        parent = parent_hash or ZERO_HASH
        record = RegistryRecord(
            report_id=report.report_id,
            report_hash=h,
            parent_hash=parent,
            chain_id=await self.chain_id(),
            contract_address=self.address,
        )

        existing = await self.find_by_hash(h)
        if existing is not None:
            if not reporter_trusted(self, existing.reporter):
                # Someone copied our pending tx's hash from the mempool and registered it first. They now own the
                # record and could supersede it; never present it as ours.
                raise ChainError("HashClaimedByAnotherReporter", existing.reporter)
            return record.model_copy(
                update={"onchain_id": existing.id, "reporter_address": existing.reporter, "status": existing.status}
            )

        if self._account is None:
            raise ChainError("NotConfigured", "RELAYER_PRIVATE_KEY is not set")
        acct = self._account
        fn = self._contract.functions.submitReport(_hex32(h), _hex32(parent))

        async with self._send_lock:
            nonce = await self._call(self._w3.eth.get_transaction_count(acct.address, "pending"))
            tx = await self._call(fn.build_transaction({"from": acct.address, "nonce": nonce}))  # estimates gas
            signed = acct.sign_transaction(tx)
            tx_hash = _to_hex(await self._call(self._w3.eth.send_raw_transaction(signed.raw_transaction)))
        log.info("registry submit sent report_id=%s tx=%s", report.report_id, tx_hash)

        try:
            receipt = await self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=self._receipt_timeout_s)
        except TimeExhausted as e:
            raise ChainUnavailable(f"tx {tx_hash} not mined within {self._receipt_timeout_s}s") from e
        if receipt["status"] != 1:
            raise ChainError("Reverted", f"tx {tx_hash} reverted")

        events = self._contract.events.ReportSubmitted().process_receipt(receipt, errors=DISCARD)
        if not events:
            raise ChainError("NoEvent", f"tx {tx_hash} emitted no ReportSubmitted")
        ev = events[0]["args"]
        return record.model_copy(
            update={"onchain_id": ev["id"], "tx_hash": tx_hash, "reporter_address": ev["reporter"]}
        )

    # ---------- verification ----------

    async def verify(self, report: AssessmentReport, tx_hash: str | None = None) -> VerificationResult:
        computed = report_hash(report)
        onchain = await self.find_by_hash(computed)
        return VerificationResult(
            report_id=report.report_id,
            computed_hash=computed,
            onchain_hash=onchain.report_hash if onchain else None,
            match=onchain is not None and onchain.report_hash == computed and reporter_trusted(self, onchain.reporter),
            onchain_status=onchain.status if onchain else None,
            onchain_created_at=onchain.created_at if onchain else None,
            tx_hash=tx_hash,
            explorer_url=await self.explorer_url(tx_hash),
        )

    # ---------- internals ----------

    async def _call(self, awaitable: Any) -> Any:
        try:
            return await awaitable
        except (ContractCustomError, ContractLogicError) as e:
            raise _decode_revert(e) from e
        except (TimeoutError, Web3Exception, OSError) as e:
            raise ChainUnavailable(type(e).__name__) from e
        except Exception as e:  # aiohttp client errors etc. — don't leak RPC URLs (may embed API keys)
            if type(e).__module__.startswith("aiohttp"):
                raise ChainUnavailable(type(e).__name__) from e
            raise
