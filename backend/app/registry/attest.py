"""Reporter provenance (M6-3): an optional EIP-712 signature by the user's own wallet over a report hash.

The relayer still pays gas and is the on-chain `reporter`, so on-chain every report has the same reporter. A user
who wants their own address tied to a report signs typed data naming the report hash; we verify the signature,
store it off-chain and show the signer. Anyone can re-check it from report.json, the typed data and the signature.
Cheaper than direct submission (no gas for the user, the registry stays permissioned) at the cost of not being
on-chain: the signature lives in our database, so it proves who vouched, not that the chain recorded it.
"""
from __future__ import annotations

from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data

STATEMENT = "I am submitting this CyberMatrix report and vouch for the evidence it contains."


def typed_data(report_hash: str, report_id: str, chain_id: int, contract: str) -> dict[str, Any]:
    return {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
            "ReportAttestation": [{"name": "reportHash", "type": "bytes32"}, {"name": "reportId", "type": "string"},
                                  {"name": "statement", "type": "string"}],
        },
        "primaryType": "ReportAttestation",
        "domain": {"name": "CyberMatrix ThreatRegistry", "version": "1", "chainId": chain_id,
                   "verifyingContract": contract},
        "message": {"reportHash": report_hash, "reportId": report_id, "statement": STATEMENT},
    }


def recover(data: dict[str, Any], signature: str) -> str:
    """Checksummed signer address. Raises ValueError on a malformed signature."""
    try:
        return Account.recover_message(encode_typed_data(full_message=data), signature=signature)
    except Exception as e:  # noqa: BLE001  (eth_account raises several types for bad input)
        raise ValueError("signature could not be verified") from e
