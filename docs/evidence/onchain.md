# On-chain evidence (captured 2026-11-10)

Registry v3 `0x5De4Cd6F651A4D80ddA16fc70431dd669621BeeA` on Sepolia (chain 11155111).

| Item | Value | Check |
|---|---|---|
| Source verified | https://sepolia.etherscan.io/address/0x5de4cd6f651a4d80dda16fc70431dd669621beea#code | Etherscan v2 `getsourcecode`: ContractName ThreatRegistry, compiler v0.8.24+commit.e11b9ed9, 11132 chars of source |
| Deploy tx | `0xbdf33b29c1e6d07e0eb41d5742d924f21444c5c1817857d3c1c77d4ca507bb3b` | receipt status 1, block 12099038, from deployer `0xaf66…105C`, created the address above |
| submitReport tx | `0x08d6c9ef458d86e87121774a2c57439855f76b8b918ab6275e4733aee44237c5` | status 1, block 12099042, from relayer `0x1B7c…848e` |
| setStatus tx (Validated) | `0xab1eef2179649bfc7f8d32d31b3594f9a4cad7d1c5806f24dc0714dfc05c36c0` | status 1, block 12099043, from validator `0xaf66…105C` |

## Calldata decoded (M6-4)

`submitReport` input is 68 bytes: selector `0x644ca522` = `submitReport(bytes32,bytes32)` + two words.

| Field | Value |
|---|---|
| reportHash | `0xe8db935c3a232b5389c14869c1d0ace58d0f38c6231d1ecff0fecdceb2ad91d3` (keccak256 of the canonical sample report) |
| parentHash | `0x00…00` (first version) |

Its single log (`ReportSubmitted`): topics = event sig, id `1`, reportHash, reporter `0x1b7c…848e`; data = parentHash (zero).
Block timestamp is the only time. No URL, message, email or other text.

`setStatus` input is 68 bytes: selector `0xd896dd64` = `setStatus(uint256,uint8)`, id `1`, status `2` (Validated).

Commands: `cast tx <hash> input`, `cast calldata-decode`, `cast receipt <hash> logs` against `$SEPOLIA_RPC_URL`.

## Dispute and resolution (D-5, sent 2026-11-10)

On-chain report #2 (hash `0xcfbb58c1…9463`, submitted by the relayer). Both transactions sent from the deployer
`0xaf66…105C`, which is also the only validator, so the disputer and the resolver are the same key in this demo.

| Step | Tx | Block | Result |
|---|---|---|---|
| `disputeReport(2, reasonHash)` with 0.001 ETH bond | `0x2ac133a3678fd312b7d48de477e411346afa92f12c2bb0c763df5edafad0cd8a` | 12100020 | status 1; report #2 → Disputed |
| `setStatus(2, Validated)` | `0x98b5683ff793987e27041be7502791d3abb8e9cf5f6e21ebc335939e3752c7d8` | 12100022 | status 1; report #2 → Validated; bond credited to the owner (`pendingWithdrawal` = 1e15 wei, not withdrawn) |

reasonHash = keccak256 of the text "Audit demo 2026-11-10: dispute raised to exercise the bonded dispute and validator
resolution flow." = `0x81dc34f07173701427eb3a33fdd04d1e95170aa295f94fe75ddacb6266bf8006`.
