# eMudhra distrust fixtures

Public certificates only, downloaded from crt.sh by `scripts/fill_distrusted_spki.py`. The script checks each file's
SHA-256 against `data/distrusted_cas.json` before saving it. No private keys are stored here, and nothing is ever
signed with the compromised eMudhra keys. Tests build their own throwaway leaves and CAs with `tests/certgen.py`.

## Why 18 files for 17 entries

`distrusted_cas.json` has 17 `entries`, one file per entry. The 18th file is the removed root, which is listed
under `removed_roots` and not under `entries`:

| Files | Count | Listed in |
|---|---|---|
| `<intermediate>.pem` | 8 | `entries`, relation `original` |
| `<intermediate>__xsign_<crt.sh id>.pem` | 8 | `entries`, relation `cross_sign` (issued by Sectigo "AAA Certificate Services") |
| `<intermediate>__reissue_<crt.sh id>.pem` | 1 | `entries`, relation `reissue` (DV G3B, issued again by "emSign Root TLS CA - G3") |
| `root_emsign_ecc_root_ca_g3_<sha256 prefix>.pem` | 1 | `removed_roots` |

The root `emSign ECC Root CA - G3` is not a compromised key. It was removed from Mozilla NSS and Chrome, so the
check reports it as `TLS.REMOVED_ROOT` (high), not `TLS.DISTRUSTED_CA` (critical). It is not the issuer of these
intermediates either: they chain to `emSign Root TLS CA - G3`, which that ECC root cross-signs. The fixture is
used as the top of the verified chain in `test_removed_root_only_is_high_not_critical`, so the removed-root path
is tested with the real certificate instead of a stand-in.

`test_every_entry_has_a_matching_fixture` fails if a file exists that is neither an entry nor a removed root.

## Key invariant

The 17 entries carry exactly 8 distinct SPKI hashes, one for each original intermediate. Every cross-sign and
re-issue re-uses an original's key, which is why matching by SPKI catches certificates whose own hash is missing
from the list (`test_real_reissue_matches_by_spki_alone`).
