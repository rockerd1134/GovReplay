# B.run local third-party boundary probes

All fixtures use generated local keys and data. Raw output, private keys, signed metadata, Git repositories and command logs belong under ignored `git/software/runs/third-party-boundary/`. No hosted service or third-party repository is contacted by a probe. The build steps fetch pinned public releases; the running containers use `network_mode: none` or `--network none`.

From `git/software`:

```powershell
docker compose -f compose.third-party-boundary.yaml build
docker compose -f compose.third-party-boundary.yaml run --rm in-toto-probe
foreach ($case in @('control','T2','T3','T7','T5_T8')) {
  foreach ($repeat in 1,2) {
    docker compose -f compose.third-party-boundary.yaml run --rm gittuf-probe `
      --binary /usr/local/bin/gittuf `
      --out "/out/gittuf-compose-$case-$repeat" --case $case
  }
}
python packages/experiments/third-party-boundary/run_cosign.py `
  --out runs/third-party-boundary/cosign-1
python packages/experiments/third-party-boundary/verify_results.py `
  --runs runs/third-party-boundary
```

Choose a fresh output name on rerun; the harness refuses to overwrite existing fixtures. The Cosign script uses host Python only to orchestrate pinned, network-disabled containers. The target signing and verification commands run in `ghcr.io/sigstore/cosign/cosign:v3.1.3` at digest `sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8`. Gittuf v0.16.0's Linux binary is SHA-256 checked during image build. in-toto 3.1.0 and its Python dependencies are pinned in its Dockerfile. Both images use the pinned Python base digest in the Dockerfiles.

The analogs are deliberately limited. in-toto has no authoritative local link commitment N; a signed-layout swap models removal from its selected policy. Cosign key-based blob verification has no N, admission, Fulcio, Rekor, or TSA; selecting a different public key models a trust-set change. Gittuf's N is the recorded reference update. T6 is unavailable in the gittuf control because a signature added to a Git commit changes its object identity; the harness does not rewrite a recorded reference to mimic it. The programs emit exit codes and raw diagnostics. `verify_results.py` compares these records to the frozen predictions; the context synthesis explains what those observations support.
