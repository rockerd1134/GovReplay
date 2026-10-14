"""Local in-toto boundary probe; all generated metadata is written under --out."""

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from in_toto.models.layout import Layout, Step
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from securesystemslib.signer import CryptoSigner

CASES = ("control", "T2", "T3", "T6", "T7", "T5_T8")


def stamp():
    return datetime.now(timezone.utc).isoformat()


def public(signer):
    value = signer.public_key.to_dict()
    value["keyid"] = signer.public_key.keyid
    return value


def write_layout(path, owner, functionary):
    layout = Layout()
    layout.add_functionary_key(public(functionary))
    layout.set_relative_expiration(days=1)
    step = Step(name="build")
    step.pubkeys = [functionary.public_key.keyid]
    layout.steps = [step]
    metadata = Metablock(signed=layout)
    metadata.create_signature(owner)
    metadata.dump(str(path))


def write_link(directory, signer):
    link = Link(name="build", materials={}, products={}, command=[], byproducts={})
    metadata = Metablock(signed=link)
    metadata.create_signature(signer)
    metadata.dump(str(directory / f"build.{signer.public_key.keyid[:8]}.link"))


def verify(layout, key_path, link_dir):
    command = ["in-toto-verify", "--layout", str(layout),
               "--verification-keys", str(key_path), "--link-dir", str(link_dir)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return {"command": command, "time_utc": stamp(), "exit_code": completed.returncode,
            "stdout": completed.stdout, "stderr": completed.stderr}


def run_case(root, case, repeat):
    directory = root / f"{case}-{repeat}"
    directory.mkdir(parents=True, exist_ok=False)
    owner = CryptoSigner.generate_ed25519()
    p = CryptoSigner.generate_ed25519()
    q = CryptoSigner.generate_ed25519()
    original = directory / "original.layout"
    removed = directory / "removed.layout"
    write_layout(original, owner, p)
    write_layout(removed, owner, q)
    key_path = directory / "owner.pub"
    owner_public_bytes = bytes.fromhex(owner.public_key.keyval["public"])
    key_path.write_bytes(Ed25519PublicKey.from_public_bytes(owner_public_bytes).public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    transitions = []

    def event(name):
        transitions.append({"event": name, "time_utc": stamp()})

    if case == "T3":
        event("R_select_removed_layout")
        write_link(directory, p)
        event("S_sign_with_retained_P_key")
    elif case == "T6":
        event("N_local_file_marker_only")
        write_link(directory, p)
        event("S_sign_after_marker")
    elif case == "T7":
        event("R_select_removed_layout")
        event("G_select_original_layout")
        write_link(directory, p)
        event("S_sign")
    else:
        write_link(directory, p)
        event("S_sign")
        if case == "T2":
            event("R_select_removed_layout")
    selected = removed if case in ("T2", "T3") else original
    event("AUDIT_start")
    observations = [{"phase": "selected", **verify(selected, key_path, directory)}]
    if case == "T5_T8":
        event("R_select_removed_layout")
        observations.append({"phase": "after_R", **verify(removed, key_path, directory)})
        observations.append({"phase": "retained_original", **verify(original, key_path, directory)})
    return {"target": "in-toto", "version": "3.1.0", "case": case,
            "repeat": repeat, "events": transitions, "observations": observations,
            "layout_owner_keyid": owner.public_key.keyid,
            "P_keyid": p.public_key.keyid, "replacement_keyid": q.public_key.keyid}


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
