# Third-party dependencies and credits

GovReplay's owned source is released under Apache-2.0. Dependencies keep their
own licenses; the project license does not relicense them. This repository does
not vendor the downloaded Foundry libraries or container images.

| Component | Pin | License / upstream |
| --- | --- | --- |
| OpenZeppelin Contracts | v5.0.2 | MIT; <https://github.com/OpenZeppelin/openzeppelin-contracts> |
| forge-std | v1.9.6 | MIT OR Apache-2.0; <https://github.com/foundry-rs/forge-std> |
| Foundry | v1.0.0 image | MIT OR Apache-2.0; <https://github.com/foundry-rs/foundry> |
| Hyperledger Besu | 25.6.0 image | Apache-2.0; <https://github.com/hyperledger/besu> |
| Cedar policy library | 4.11.1 | Apache-2.0; <https://github.com/cedar-policy/cedar> |
| serde_json | 1.0.150 | MIT OR Apache-2.0; <https://github.com/serde-rs/json> |
| sha2 | 0.10.9 | MIT OR Apache-2.0; <https://github.com/RustCrypto/hashes> |
| Node.js | 24.2.0 image | Node's bundled LICENSE includes MIT and dependency notices; <https://github.com/nodejs/node> |
| Rust | 1.89.0 image | MIT OR Apache-2.0 plus bundled dependencies; <https://github.com/rust-lang/rust> |
| curl | 8.10.1 image | curl license plus image dependencies; <https://curl.se/docs/copyright.html> |

Rust transitive versions are locked in `packages/policy-service/Cargo.lock`;
their source-package license notices remain with Cargo's downloaded crates.
When distributing built images/binaries rather than this source artifact,
retain the upstream notices for every included dependency and base-image package.

Optional third-party boundary probes invoke pinned in-toto, securesystemslib,
cryptography, gittuf and Cosign, along with Python dependencies listed in their
Dockerfiles. Their upstream licenses and notices govern those installed tools:
<https://github.com/in-toto/in-toto>,
<https://github.com/secure-systems-lab/securesystemslib>,
<https://github.com/pyca/cryptography>,
<https://github.com/gittuf/gittuf>,
<https://github.com/sigstore/cosign>.

Downloaded dependency source, keys, build products and images are generated
local state, not part of the Git release. Inspect their licenses when creating
additional distributions; this file is not a blanket statement about arbitrary
future dependencies.
