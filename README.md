# CyberMatrix

AI-powered web threat detection and digital trust intelligence. Submit a URL, domain, email, message or QR
image and get an evidence-based risk assessment. Reports can be committed on-chain and verified by anyone,
without trusting our backend.

## On-chain registry (Sepolia)

| | |
|---|---|
| Contract | [`0x22Cc4217bD5639F5b7159eDA584AC066eb8e73bc`](https://sepolia.etherscan.io/address/0x22cc4217bd5639f5b7159eda584ac066eb8e73bc#code) (source verified) |
| Deploy tx | [`0xedcaba82…b2b5`](https://sepolia.etherscan.io/tx/0xedcaba82855b682b40d8922dde770c954819f2f195b5c1b1c423de289100b2b5), block 12095596 |
| Sample report registration | [`0xc8ee7619…11e6`](https://sepolia.etherscan.io/tx/0xc8ee76192618f92a5e447bb83874b12e37a7e4cf916485ba3a13e9dfaaf811e6) (report #1, status `validated`) |

Only the report hash, parent hash, status, timestamps and reporter address are stored on-chain. URLs, messages
and any personal data stay off-chain. Each report includes a random 32-byte salt, so the hash can't be
brute-forced back to a URL.

Roles: the deployer is owner and the only validator. The backend relayer can only submit reports. Anyone can
dispute a report. Machine-readable details are in [`contracts/deployments/sepolia.json`](contracts/deployments/sepolia.json).

## Verify a report yourself

```bash
uv run verify/verify.py --report backend/tests/fixtures/sample_report.json \
  --rpc https://ethereum-sepolia-rpc.publicnode.com \
  --address 0x22Cc4217bD5639F5b7159eDA584AC066eb8e73bc
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

After changing `backend/app/schemas.py` or any route, regenerate the frontend types: `cd frontend && npm run gen`.

## Development

```bash
cd contracts && forge test -vv          # 46 tests, 100% branch coverage
uv run --no-project --with-requirements verify/requirements.txt --with pytest pytest verify/tests -q
```

Design notes are in `docs/` (risk engine rules, library decisions).
