"""Local gittuf v0.16.0 control; repository and keys live under ignored --out."""

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def stamp():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--case", required=True,
                        choices=("control", "T2", "T3", "T7", "T5_T8"))
    args = parser.parse_args()
    binary = args.binary.resolve()
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    repo = root / "repo"
    repo.mkdir()
    commands = []
    events = []

    def event(name):
        events.append({"event": name, "time_utc": stamp()})
        (root / "events.json").write_text(json.dumps(events, indent=2) + "\n")

    def call(command, cwd=repo, must_pass=True):
        result = subprocess.run([str(x) for x in command], cwd=cwd,
                                capture_output=True, text=True, check=False)
        record = {"command": [str(x) for x in command], "time_utc": stamp(),
                  "exit_code": result.returncode, "stdout": result.stdout,
                  "stderr": result.stderr}
        commands.append(record)
        (root / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if must_pass and result.returncode:
            raise RuntimeError(f"failed: {command}: {result.stderr}")
        return record

    keys = root / "keys"
    keys.mkdir()
    for name in ("admin", "p", "q"):
        call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keys / name], root)
    admin = keys / "admin"
    p = keys / "p"
    call(["git", "init", "-b", "main", str(repo)], root)
    for key, value in (("user.name", "B-run administrator"),
                       ("user.email", "b-run@example.invalid"),
                       ("gpg.format", "ssh"), ("user.signingkey", str(admin)),
                       ("commit.gpgsign", "true")):
        call(["git", "config", "--local", key, value])
    (repo / "README.md").write_text("local gittuf control\n")
    call(["git", "add", "README.md"])
    call(["git", "commit", "-m", "initial"])
    call([binary, "trust", "init", "-k", admin])
    call([binary, "trust", "add-policy-key", "-k", admin, "--policy-key", f"{admin}.pub"])
    call([binary, "trust", "stage", "--local-only", "-k", admin])
    call([binary, "trust", "apply", "--local-only", "-k", admin])
    call([binary, "policy", "init", "-k", admin])
    call([binary, "policy", "add-person", "-k", admin, "--person-ID", "P",
          "--public-key", f"{p}.pub"])
    call([binary, "policy", "add-person", "-k", admin, "--person-ID", "Q",
          "--public-key", f"{keys / 'q'}.pub"])
    call([binary, "policy", "add-rule", "-k", admin, "--rule-name", "main-writer",
          "--rule-pattern", "git:refs/heads/main", "--authorize", "P"])
    call([binary, "policy", "stage", "--local-only", "-k", admin])
    call([binary, "policy", "apply", "--local-only", "-k", admin])

    def rule(principal, label):
        call([binary, "policy", "update-rule", "-k", admin, "--rule-name", "main-writer",
              "--rule-pattern", "git:refs/heads/main", "--authorize", principal])
        call([binary, "policy", "stage", "--local-only", "-k", admin])
        call([binary, "policy", "apply", "--local-only", "-k", admin])
        event(label)

    if args.case in ("T3", "T7"):
        rule("Q", "R_policy_excludes_P")
    if args.case == "T7":
        rule("P", "G_policy_restores_P")
    call(["git", "config", "--local", "user.signingkey", str(p)])
    (repo / "change.txt").write_text("signed by P\n")
    call(["git", "add", "change.txt"])
    call(["git", "commit", "-m", "P signed change"])
    event("S_P_signed_commit")
    if args.case == "T2":
        rule("Q", "R_policy_excludes_P")
    call([binary, "rsl", "record", "main", "--local-only"])
    event("N_RSL_reference_record")
    first = call([binary, "verify-ref", "main"], must_pass=False)
    if args.case == "T5_T8":
        rule("Q", "R_policy_excludes_P")
        later = call([binary, "verify-ref", "main"], must_pass=False)
    else:
        later = None
    call(["git", "log", "-n", "8", "--format=%H %cI %s", "refs/gittuf/reference-state-log"])
    print(json.dumps({"case": args.case, "binary": str(binary), "out": str(root),
                      "first_exit_code": first["exit_code"],
                      "later_exit_code": None if later is None else later["exit_code"]}))


if __name__ == "__main__":
    main()
