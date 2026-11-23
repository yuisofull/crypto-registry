# crypto-registry

Fetches upstream cryptography metadata pinned to exact commits, parses it into
typed records, and merges it into one registry of algorithms and curves. Each
record has an OID, primitive, NIST quantum level and classical security bits,
and every value carries a reference to where it came from.

```bash
pip install -r requirements.txt
python fetch.py          # pinned upstream files -> data/raw/ (+ manifest.json with sha256)
python parse.py          # optional: per-source JSON -> data/parsed/ (for inspection)
python merge.py          # -> data/merged/registry.json, registry.csv, conflicts.json, excluded_openssl.json
python -m pytest -q      # tests, including `mypy --strict` and an OID cross-check against local libcrypto

python fetch.py --bump   # move sources to branch heads, rewrite sources.yml, fetch
python fetch.py --check  # verify data/raw/ against the manifest, no network
python merge.py --fail-on-conflict   # for CI
```

## Inputs

| Source | Used for |
|---|---|
| openssl `crypto/objects/objects.txt` | OID ↔ short/long name |
| oqs-provider `oqs-template/generate.yml` | PQC/hybrid/composite OIDs, TLS code points |
| liboqs `docs/cbom.json` + `src/kem/kem.h`, `src/sig/sig.h` | PQC parameter sets, NIST level; headers give the exact join key to oqs-provider |
| CycloneDX `schema/cryptography-defs.json` | family/primitive by name pattern, curves with OIDs and aliases |
| `curated/nist.yml` | transcribed NIST tables: IR 8547 (Tables 1, 2, 4, 6, 7, 8), SP 800-57 Pt1 r5 (Table 2), SP 800-186 (Table 1) |
| `curated/oid_arcs.yml` | family/primitive for classical OIDs, each rule citing its RFC or NIST CSOR |

Fetched sources are pinned in `sources.yml`. The cited documents are listed
there under `documents`, and every curated row names one of them.

## Types

- `parsers/_input.py` is the only place untrusted JSON/YAML is touched. `Obj`
  getters check runtime types and raise `ParseError` with the exact path
  (`generate.yml.kems[3].enable_kem: expected bool, got str`).
- `parsers/models.py` holds frozen dataclasses for each source. `registry/models.py`
  holds the merged `Record`. Closed sets are enums: `Primitive` (CycloneDX
  values), `NistLevel` (0..5), `Composition`, `Inclusion`, `Field`.
- `mypy --strict` runs as a test, with `disallow_any_explicit` on.

## Merged record

```json
{
  "id": "oid:2.16.840.1.101.3.4.4.2",
  "name": "ML-KEM-768",
  "record_type": "algorithm",
  "composition": "single",
  "family": "ML-KEM",
  "oid": "2.16.840.1.101.3.4.4.2",
  "primitive": "kem",
  "parameterSetIdentifier": "ML-KEM-768",
  "curve": null,
  "classicalSecurityLevel": null,
  "nistQuantumSecurityLevel": 3,
  "aliases": ["OQS_KEM_alg_ml_kem_768", "id-alg-ml-kem-768", "mlkem768"],
  "tls_codepoint": 513,
  "components": [],
  "hash_strength": null,
  "experimental_oid": false,
  "included_by": ["liboqs", "openssl:pqc-oid", "oqs-provider"],
  "refs": {"nistQuantumSecurityLevel": [{"url": "https://github.com/open-quantum-safe/liboqs/blob/<commit>/docs/cbom.json", "locator": null}], "...": []}
}
```

camelCase keys are CycloneDX `algorithmProperties` names, so converting to a
CBOM component is a field copy. snake_case keys are registry-only.

- `id`: `oid:<oid>` when there is an OID, else `algorithm:<key>` / `curve:<key>`.
- `refs`: per field, a permalink to the pinned commit (with line number for
  objects.txt), or a document URL plus `locator` ("Table 6, §4.1.3", "Appendix A.2.4").
- Hybrids and composites: `nistQuantumSecurityLevel` is the PQ part's level.
  `classicalSecurityLevel` is null, and the classical part's bits are in `components`.
- Hashes/XOFs: `classicalSecurityLevel` / `nistQuantumSecurityLevel` hold the
  collision values. Preimage values are in `hash_strength`.
- AES modes (GCM, CBC, key wrap) take the IR 8547 Table 6 level of their key size.
- RSA/EC/DH key-type OIDs (`rsaEncryption`, `id-ecPublicKey`) have
  `primitive: null`, and their classical bits depend on the key, so they are null too.

## Merge order and conflicts

1. oqs-provider pure algorithms joined to liboqs on `oqs_id`, then liboqs-only parameter sets
2. oqs-provider hybrids and composites (default ECP hybrids named from the PQ level)
3. OpenSSL objects, kept if: OID already known from PQC, a rule in `curated/oid_arcs.yml`
   matches, the OID is a CycloneDX curve OID, or a name matches a CycloneDX pattern
4. CycloneDX curves (nist group name is canonical; secg/x962 names become aliases)
5. Curated NIST values: named-curve bits, hash and symmetric levels, level 0 for
   quantum-vulnerable families

The first source to set a field wins. A later source that disagrees is written
to `conflicts.json` instead of overwriting.

OpenSSL objects that are dropped are listed with a reason in `excluded_openssl.json`.
To include more, add a cited rule to `curated/oid_arcs.yml`. Known gaps: DH
(PKCS #3), Blowfish, SEED, BLAKE2, GOST, SM2 signatures, PKCS #12 PBE.

## Still to do by hand

- `curated/nist.yml`: every table has `verified: false` until it has been checked
  against the PDF, and `merge.py` warns until then. Check the RSA row of IR 8547
  Table 4 first: the text extraction was garbled around it.
- `registry_families` in `curated/nist.yml` maps IR 8547 algorithm names to
  CycloneDX family names. That mapping is ours, not NIST's.

## Known limits

- CycloneDX name patterns have untyped placeholders, so a few name-matched
  records get a loose primitive (e.g. `CAMELLIA-128-CMAC` -> block-cipher).
  These records have `included_by: ["openssl:registry-name"]` and a registry ref.
- oqs-provider composite OIDs under `1.3.9999.*` are OQS test arcs (`experimental_oid: true`).
- Licenses of fetched data: OpenSSL and CycloneDX Apache-2.0, liboqs and
  oqs-provider MIT. Keep attribution if you commit generated output.
