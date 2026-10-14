# Research artifact security boundaries

GovReplay is a local research prototype. Use disposable wallets, synthetic
identities and isolated development chains. Never fund fixture accounts on a
public network or reuse their keys.

## Keys and credentials

The primary reproduction helper generates fresh random administrator/actor
wallets using the pinned Foundry image. Keys stay in ignored
`.tmp/ciss-<RunId>/runtime.json`; generated validator keys and receipts stay in
ignored chain/run directories. Local administrators can inspect container
environments and process arguments. Do not use production keys with these scripts.

Historical signed fixtures and deterministic scenario/policy/gateway paths use
small public synthetic key scalars. They are test vectors, not protected
credentials. They preserve reproducible signatures and comparisons. These paths
are marked as fixture/demo code; the gateway is not an authenticated agent service.
The legacy genesis funds a synthetic address; the reproduction helper substitutes
its fresh administrator address in an isolated genesis.

Do not commit private PEM/SSH/wallet keys, tokens, real environment files,
validator data, generated archives or broadcasts. Ignore rules are not substitutes
for scanning Git history. If real credentials are found, revoke/rotate them and
inspect all affected histories before publication.

## Local services

Primary reproduction chains publish no host ports. Optional Besu profiles publish
RPC on `127.0.0.1` only, restrict host names and use default restricted CORS.
RPC remains unauthenticated within the local Docker network. ETH/NET/WEB3/QBFT
APIs and zero gas price support controlled experiments. Do not proxy them publicly.

The optional four-node profile's `172.28.0.0/24` addresses are synthetic Docker
peer settings, not deployment credentials. The static UI binds to localhost and
rejects paths and symlinks outside its public directory.

## Enforcement and residual risks

The generic `ProvenanceRegistry` intentionally remains the evaluated comparator.
`HardenedProvenanceRegistry` checks the actor's deployer role for action-proposal
commitments; it does not validate signatures or their creation order at write time.
See [evaluation scope](docs/ciss-evaluation.md).

The handwritten secp256k1/Keccak implementation is experimental and has not been
audited for production cryptography. CLI file paths are trusted local inputs.
Container profiles mount their repository read/write for generated outputs.

Release review combines Gitleaks history/tree scanning with targeted inspection
of keys, network exposure, dependency provenance and file serving. A passing scan
does not guarantee absence of vulnerabilities. Report redacted file/commit
locations to the maintainer; never post secret values in an issue or log.
