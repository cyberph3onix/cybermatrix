#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["web3>=7,<8", "rfc8785>=0.1.4", "eth-hash[pycryptodome]>=0.7"]
# ///
"""Independent verifier for CyberMatrix reports. Needs no backend.

    python verify/verify.py --report report.json --rpc $SEPOLIA_RPC_URL --address $REGISTRY_ADDRESS

Computes keccak256(RFC8785-JCS(report)) and checks it against the ThreatRegistry contract.
Exit codes: 0 = MATCH, 1 = MISMATCH, 2 = usage / file / RPC error.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785
from eth_hash.auto import keccak

EXIT_MATCH, EXIT_MISMATCH, EXIT_ERROR = 0, 1, 2

STATUS_NAMES = ["submitted", "disputed", "validated", "rejected", "superseded"]
EXPLORERS = {1: "https://etherscan.io", 11155111: "https://sepolia.etherscan.io"}
NOTE = (
    "A matching hash proves this report is unchanged since it was registered. "
    "It does not prove the report's conclusions are true."
)

# Minimal ABI: the two read functions plus the event used to find the registering transaction.
ABI: list[dict[str, Any]] = [
    {
        "type": "function",
        "name": "idOfHash",
        "stateMutability": "view",
        "inputs": [{"name": "reportHash", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "getReport",
        "stateMutability": "view",
        "inputs": [{"name": "id", "type": "uint256"}],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "reportHash", "type": "bytes32"},
                    {"name": "parentHash", "type": "bytes32"},
                    {"name": "reporter", "type": "address"},
                    {"name": "createdAt", "type": "uint64"},
                    {"name": "status", "type": "uint8"},
                ],
            }
        ],
    },
    {
        "type": "event",
        "name": "ReportSubmitted",
        "anonymous": False,
        "inputs": [
            {"name": "id", "type": "uint256", "indexed": True},
            {"name": "reportHash", "type": "bytes32", "indexed": True},
            {"name": "parentHash", "type": "bytes32", "indexed": False},
            {"name": "reporter", "type": "address", "indexed": True},
        ],
    },
]


def compute_hash(report: Any) -> str:
    """keccak256 over the RFC 8785 canonical JSON of the parsed report."""
    return "0x" + keccak(rfc8785.dumps(report)).hex()


def load_report(path: Path) -> Any:
    with path.open("rb") as f:
        return json.load(f)


def _block_at(w3: Any, timestamp: int, lo: int) -> int:
    """Lowest block number whose timestamp is >= `timestamp` (binary search, ~log2(height) header reads)."""
    hi = w3.eth.block_number
    while lo < hi:
        mid = (lo + hi) // 2
        if w3.eth.get_block(mid)["timestamp"] < timestamp:
            lo = mid + 1
        else:
            hi = mid
    return lo


def _find_tx(w3: Any, contract: Any, report_id: int, created_at: int, from_block: int) -> str | None:
    """Locate the registering tx without wide eth_getLogs ranges (free RPC tiers cap them at ~10 blocks).

    `createdAt` is block.timestamp of the submitting block, so we binary-search for the blocks carrying exactly
    that timestamp (one block on Ethereum's 12 s slots; possibly several on a dev chain) and query only those.
    Best effort: on any failure, return None.
    """
    try:
        first = _block_at(w3, created_at, from_block)
        last = _block_at(w3, created_at + 1, first)  # first block after; inclusive bound is harmless
        logs = contract.events.ReportSubmitted.get_logs(
            from_block=first, to_block=last, argument_filters={"id": report_id}
        )
    except Exception:  # noqa: BLE001 - any RPC failure → fall back to the address link
        return None
    for log in logs:
        return "0x" + bytes(log["transactionHash"]).hex()
    return None


def verify(report_path: Path, rpc: str, address: str, from_block: int = 0) -> dict[str, Any]:
    from web3 import Web3

    computed = compute_hash(load_report(report_path))
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 15}))
    contract = w3.eth.contract(address=Web3.to_checksum_address(address), abi=ABI)
    chain_id = w3.eth.chain_id
    explorer = EXPLORERS.get(chain_id)

    result: dict[str, Any] = {
        "result": "MISMATCH",
        "computed_hash": computed,
        "onchain_hash": None,
        "chain_id": chain_id,
        "contract": contract.address,
        "note": NOTE,
    }

    report_id = contract.functions.idOfHash(bytes.fromhex(computed[2:])).call()
    if report_id == 0:
        result["reason"] = "hash is not registered in this contract"
        if explorer:
            result["explorer_url"] = f"{explorer}/address/{contract.address}"
        return result

    report_hash, parent_hash, reporter, created_at, status = contract.functions.getReport(report_id).call()
    onchain = "0x" + bytes(report_hash).hex()
    result.update(
        onchain_id=report_id,
        onchain_hash=onchain,
        parent_hash="0x" + bytes(parent_hash).hex(),
        reporter=reporter,
        status=STATUS_NAMES[status] if status < len(STATUS_NAMES) else f"unknown({status})",
        created_at=datetime.fromtimestamp(created_at, tz=UTC).isoformat().replace("+00:00", "Z"),
    )
    if onchain.lower() == computed.lower():
        result["result"] = "MATCH"
    else:  # should be impossible for a correct contract; reported rather than trusted
        result["reason"] = "on-chain record hash differs from computed hash"

    tx = _find_tx(w3, contract, report_id, created_at, from_block)
    if tx:
        result["tx_hash"] = tx
    if explorer:
        result["explorer_url"] = f"{explorer}/tx/{tx}" if tx else f"{explorer}/address/{contract.address}#events"
    return result


def _print_human(r: dict[str, Any]) -> None:
    print(r["result"])
    print(f"  computed hash : {r['computed_hash']}")
    print(f"  on-chain hash : {r['onchain_hash'] or '-'}")
    if r.get("reason"):
        print(f"  reason        : {r['reason']}")
    if r.get("onchain_id") is not None:
        print(f"  report id     : {r['onchain_id']}")
        print(f"  status        : {r['status']}")
        print(f"  registered at : {r['created_at']}")
        print(f"  reporter      : {r['reporter']}")
        if int(r["parent_hash"], 16):
            print(f"  supersedes    : {r['parent_hash']}")
    print(f"  contract      : {r['contract']} (chain {r['chain_id']})")
    if r.get("tx_hash"):
        print(f"  tx            : {r['tx_hash']}")
    if r.get("explorer_url"):
        print(f"  etherscan     : {r['explorer_url']}")
    print(f"\n{r['note']}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Verify a CyberMatrix report against the on-chain ThreatRegistry.")
    p.add_argument("--report", required=True, type=Path, help="report.json as downloaded from CyberMatrix")
    p.add_argument("--rpc", required=True, help="Ethereum JSON-RPC URL (e.g. a Sepolia endpoint)")
    p.add_argument("--address", required=True, help="ThreatRegistry contract address")
    p.add_argument("--from-block", type=int, default=0, help="first block to search for the registering tx")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = p.parse_args(argv)

    try:
        result = verify(args.report, args.rpc, args.address, args.from_block)
    except (OSError, ValueError) as e:  # unreadable file, bad JSON, bad address
        print(f"ERROR: {e}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as e:  # noqa: BLE001 - any RPC / contract call failure → exit 2
        print(f"ERROR: could not query the registry: {type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_human(result)
    return EXIT_MATCH if result["result"] == "MATCH" else EXIT_MISMATCH


if __name__ == "__main__":
    sys.exit(main())
