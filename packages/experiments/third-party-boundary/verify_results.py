"""Check saved target exit codes against the frozen B.run predictions."""

import argparse
import json
from pathlib import Path

EXPECTED = {
    "control": {"selected": 0},
    "T2": {"selected": 1},
    "T3": {"selected": 1},
    "T6": {"selected": 0},
    "T7": {"selected": 0},
    "T5_T8": {"selected": 0, "after_R": 1, "retained_original": 0},
}
GITTUF_EXPECTED = {"control": (0, None), "T2": (1, None),
                   "T3": (1, None), "T7": (0, None), "T5_T8": (0, 0)}


def check_primary(path, name):
    rows = json.loads(path.read_text())
    assert len(rows) == 12, (name, len(rows))
    for case, expectation in EXPECTED.items():
        matches = [row for row in rows if row["case"] == case]
        assert {row["repeat"] for row in matches} == {1, 2}, (name, case)
        for row in matches:
            actual = {item["phase"]: item["exit_code"] for item in row["observations"]}
            assert actual == expectation, (name, case, actual, expectation)
    return {"target": name, "matched_case_runs": 12, "total_case_runs": 12}


def check_gittuf(root):
    matched = 0
    for case, (first_expected, later_expected) in GITTUF_EXPECTED.items():
        for repeat in (1, 2):
            folder = root / f"gittuf-compose-{case}-{repeat}"
            commands = json.loads((folder / "commands.json").read_text())
            observations = [item["exit_code"] for item in commands
                            if len(item["command"]) >= 2 and item["command"][1] == "verify-ref"]
            expected = [first_expected] if later_expected is None else [first_expected, later_expected]
            assert observations == expected, (case, repeat, observations, expected)
            events = json.loads((folder / "events.json").read_text())
            assert any(item["event"] == "N_RSL_reference_record" for item in events)
            matched += 1
    return {"target": "gittuf", "matched_case_runs": matched,
            "total_case_runs": matched, "T6": "not realizable as a later signature on the same Git commit"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", required=True, type=Path)
    args = parser.parse_args()
    root = args.runs
    results = [check_primary(root / "in-toto-compose" / "observations.json", "in-toto"),
               check_primary(root / "cosign-1" / "observations.json", "cosign"),
               check_gittuf(root)]
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
