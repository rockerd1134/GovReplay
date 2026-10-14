"""Orchestrate isolated Cosign containers; keys and raw logs stay under --out."""

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

IMAGE = "ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8"
CASES = ("control", "T2", "T3", "T6", "T7", "T5_T8")


def stamp():
    return datetime.now(timezone.utc).isoformat()


def call(directory, args, password=False):
    command = ["docker", "run", "--rm", "--network", "none", "-v",
               f"{directory.resolve()}:/work", "-w", "/work"]
    if password:
        command.extend(["-e", "COSIGN_PASSWORD="])
    command.extend([IMAGE, *args])
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    return {"command": command, "time_utc": stamp(), "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def run_case(root, case, repeat):
    directory = root / f"{case}-{repeat}"
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "blob.txt").write_text(f"B.run {case} {repeat}\n")
    commands = [call(directory, ["generate-key-pair", "--output-key-prefix", "p"], True),
                call(directory, ["generate-key-pair", "--output-key-prefix", "q"], True)]
    if any(item["exit_code"] != 0 for item in commands):
        raise RuntimeError(f"key generation failed: {case}-{repeat}")
    events = []

    def event(name):
        events.append({"event": name, "time_utc": stamp()})

    if case == "T3":
        event("R_remove_P_from_selected_trust_set")
    if case == "T7":
        event("R_remove_P_from_selected_trust_set")
        event("G_restore_P_to_selected_trust_set")
    if case == "T6":
        event("N_local_file_marker_only")
    sign = call(directory, ["sign-blob", "--key", "p.key", "--bundle", "blob.bundle.json",
                            "--tlog-upload=false", "--use-signing-config=false", "blob.txt"], True)
    commands.append(sign)
    if sign["exit_code"] != 0:
        raise RuntimeError(f"signing failed: {case}-{repeat}")
    event("S_sign_with_P")
    if case == "T2":
        event("R_remove_P_from_selected_trust_set")

    def verify(key, phase):
        result = call(directory, ["verify-blob", "--key", key, "--bundle",
                                  "blob.bundle.json", "--insecure-ignore-tlog", "blob.txt"])
        result["phase"] = phase
        return result

    selected = "q.pub" if case in ("T2", "T3") else "p.pub"
    observations = [verify(selected, "selected")]
    if case == "T5_T8":
        event("R_remove_P_from_selected_trust_set")
        observations.extend([verify("q.pub", "after_R"), verify("p.pub", "retained_original")])
    return {"target": "cosign", "version": "v3.1.3", "image": IMAGE,
            "case": case, "repeat": repeat, "events": events,
            "artifact_sha256": hashlib.sha256((directory / "blob.txt").read_bytes()).hexdigest(),
            "commands": commands, "observations": observations}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    results = [run_case(args.out, case, repeat) for case in CASES for repeat in (1, 2)]
    (args.out / "observations.json").write_text(json.dumps(results, indent=2) + "\n")
    for result in results:
        print(result["case"], result["repeat"],
              [(item["phase"], item["exit_code"]) for item in result["observations"]])


if __name__ == "__main__":
    main()
