# CyberMatrix

AI-powered web threat detection and digital trust intelligence. Submit a URL, domain, email, message or QR
image and get an evidence-based risk assessment. Reports can be committed on-chain and verified by anyone,
without trusting our backend.

## On-chain registry (Sepolia)

| | |
|---|---|
| Contract (v3) | [`0x5De4Cd6F651A4D80ddA16fc70431dd669621BeeA`](https://sepolia.etherscan.io/address/0x5de4cd6f651a4d80dda16fc70431dd669621beea#code) (source verified) |
| Deploy tx | [`0xbdf33b29…bb3b`](https://sepolia.etherscan.io/tx/0xbdf33b29c1e6d07e0eb41d5742d924f21444c5c1817857d3c1c77d4ca507bb3b), block 12099038 |
| Sample report registration | [`0x08d6c9ef…37c5`](https://sepolia.etherscan.io/tx/0x08d6c9ef458d86e87121774a2c57439855f76b8b918ab6275e4733aee44237c5) (report #1), validated in [`0xab1eef21…36c0`](https://sepolia.etherscan.io/tx/0xab1eef2179649bfc7f8d32d31b3594f9a4cad7d1c5806f24dc0714dfc05c36c0) |
| Dispute + resolution | report #2 disputed in [`0x2ac133a3…cd8a`](https://sepolia.etherscan.io/tx/0x2ac133a3678fd312b7d48de477e411346afa92f12c2bb0c763df5edafad0cd8a), validated in [`0x98b5683f…c7d8`](https://sepolia.etherscan.io/tx/0x98b5683ff793987e27041be7502791d3abb8e9cf5f6e21ebc335939e3752c7d8) |
| Dispute bond | 0.001 Sepolia ETH |

Only the report hash, parent hash, status, timestamps and reporter address are stored on-chain. URLs, messages
and any personal data stay off-chain. Each report includes a random 32-byte salt, so the hash can't be
brute-forced back to a URL.

Roles: the deployer is owner and the only validator. The backend relayer is the only authorised reporter (v3):
nobody else can submit, so a stranger can't register a forged report or front-run ours. Anyone can
dispute a report from their own wallet by posting the bond: a validator's ruling returns it (dispute upheld, report
Rejected) or keeps it (report Validated), and a reporter's revision also returns it. Collect returned bonds with
`withdraw()`. Re-assessing a link registers a new version whose `parentHash` points at the old one, which becomes
Superseded. v1 (`0x22Cc4217…73bc`) and v2 (`0x46509457…BbB4`) are retired but still readable. Machine-readable details are in [`contracts/deployments/sepolia.json`](contracts/deployments/sepolia.json).

## Verify a report yourself

```bash
uv run verify/verify.py --report backend/tests/fixtures/sample_report.json \
  --rpc https://ethereum-sepolia-rpc.publicnode.com \
  --address 0x5De4Cd6F651A4D80ddA16fc70431dd669621BeeA \
  --relayer 0x1B7c212ffC6FA799fE6131462F2C05046B8a848e
```

`verify.py` computes `keccak256(RFC8785(report.json))`, looks it up in the registry, and prints `MATCH` with
the on-chain status, timestamp and Etherscan link (exit 0), or `MISMATCH` (exit 1). It also checks on-chain that the reporter is
authorised by the registry, and `--relayer` (CyberMatrix's relayer, from `contracts/deployments/sepolia.json`) pins
the exact address: any other reporter is `UNTRUSTED_REPORTER` (exit 1). Change one character
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

Full live demo from a fresh database (resets the compose Postgres volume, loads the recorded fixtures as a fallback,
then runs the brief's test cases live; about 70 s): `scripts/demo.sh`.

After changing `backend/app/schemas.py` or any route, regenerate the frontend types: `cd frontend && npm run gen`.

## Browser extension

`extension/` holds a Manifest V3 extension: right-click a link to check it before opening it, or tick "include a
screenshot" in the popup. Optional real-time protection (off by default) quick-checks every page you open and shows
a warning before a high-risk page loads. Load it unpacked (see [`extension/README.md`](extension/README.md)).

## More than single checks

- **Organisation dashboard** (`/org`): one page for all of an organisation's domains: security posture from the
  latest assessment, new certificates from Certificate Transparency, and lookalike sites reported here.
- **Threat-intel feed**: `GET /feeds/stix` (STIX 2.1) and `GET /feeds/blocklist.txt` list links and domains from
  high-risk reports. Query strings are removed, redirect hops and allowlisted sites are never listed, and reports a
  validator rejected on-chain are left out.
- **Screenshot impersonation**: add a screenshot to a link (web app or extension). A vision model reads which
  organisation the page shows and code compares it with the domain (`PAGE.SCREENSHOT_BRAND_MISMATCH`).

## Development

```bash
cd contracts && forge test -vv          # 61 tests, 100% branch coverage
uv run --no-project --with-requirements verify/requirements.txt --with pytest pytest verify/tests -q
```

Design notes are in `docs/` (risk engine rules, library decisions).

## Licence

MIT, see [LICENSE](LICENSE).
