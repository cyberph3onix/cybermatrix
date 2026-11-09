# CyberMatrix

AI-powered web threat detection and digital trust intelligence. Submit a URL, domain, email, message or QR
image and get an evidence-based risk assessment. Reports can be committed on-chain and verified by anyone,
without trusting our backend.

## On-chain registry (Sepolia)

| | |
|---|---|
| Contract (v2) | [`0x465094577Fe42BD31d705581bD3baAB51397BbB4`](https://sepolia.etherscan.io/address/0x465094577fe42bd31d705581bd3baab51397bbb4#code) (source verified) |
| Deploy tx | [`0x6585a3d9…0d09`](https://sepolia.etherscan.io/tx/0x6585a3d9c634e5e996d58f973dfd4deb4d992647b18f1b100a511d14943c0d09), block 12097776 |
| Sample report registration | [`0x9e5e9b57…06c2`](https://sepolia.etherscan.io/tx/0x9e5e9b575060c4b0d2d9d1998ad4c488a66849e08d7cb21a88df5dc4eff806c2) (report #1), validated in [`0x7c633465…a6b`](https://sepolia.etherscan.io/tx/0x7c633465add3ac61f6dd9e6d4c90c66ac078a0a56b6d8606ba538d0fddc58a6b) |
| Dispute bond | 0.001 Sepolia ETH |

Only the report hash, parent hash, status, timestamps and reporter address are stored on-chain. URLs, messages
and any personal data stay off-chain. Each report includes a random 32-byte salt, so the hash can't be
brute-forced back to a URL.

Roles: the deployer is owner and the only validator. The backend relayer can only submit reports. Anyone can
dispute a report from their own wallet by posting the bond: a validator's ruling returns it (dispute upheld, report
Rejected) or keeps it (report Validated), and a reporter's revision also returns it. Collect returned bonds with
`withdraw()`. Re-assessing a link registers a new version whose `parentHash` points at the old one, which becomes
Superseded. v1 (`0x22Cc4217…73bc`, no bond) is retired but still readable. Machine-readable details are in [`contracts/deployments/sepolia.json`](contracts/deployments/sepolia.json).

## Verify a report yourself

```bash
uv run verify/verify.py --report backend/tests/fixtures/sample_report.json \
  --rpc https://ethereum-sepolia-rpc.publicnode.com \
  --address 0x465094577Fe42BD31d705581bD3baAB51397BbB4
```

`verify.py` computes `keccak256(RFC8785(report.json))`, looks it up in the registry, and prints `MATCH` with
the on-chain status, timestamp and Etherscan link (exit 0), or `MISMATCH` (exit 1). Change one character
in the JSON and it reports `MISMATCH`. It needs only `web3`, `rfc8785` and `eth-hash`. Without `uv`, run
`pip install -r verify/requirements.txt` and use `python verify/verify.py …`.

A match proves the report hasn't changed since it was registered. It does not prove the report's conclusions
are true.

## Running it

```bash
cp .env.example .env        # add GSB_API_KEY, VT_API_KEY, URLHAUS_AUTH_KEY (checks without a key report "unavailable")
docker compose up --build   # frontend :3000, backend :8000 (OpenAPI docs at /docs), postgres
```

On-chain writes are off under compose: the backend container ignores `SEPOLIA_RPC_URL` / `RELAYER_PRIVATE_KEY` from
`.env` (register and verify answer 503). To enable them on purpose, add `CHAIN_SEPOLIA_RPC_URL` and
`CHAIN_RELAYER_PRIVATE_KEY` to `.env`. With those set, "Register on-chain" sends a real Sepolia transaction.

For a repeatable demo without live feeds, `cd backend && uv run python -m demo.seed` loads recorded example reports
(see docs/TESTING.md).

After changing `backend/app/schemas.py` or any route, regenerate the frontend types: `cd frontend && npm run gen`.

## Development

```bash
cd contracts && forge test -vv          # 61 tests, 100% branch coverage
uv run --no-project --with-requirements verify/requirements.txt --with pytest pytest verify/tests -q
```

Design notes are in `docs/` (risk engine rules, library decisions).
