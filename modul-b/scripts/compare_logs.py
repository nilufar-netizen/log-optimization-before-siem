
import json
import sys
from pathlib import Path


REQUIRED_FIELDS = {
    "linux_auth": [
        "timestamp", "source_ip", "username",
        "outcome", "process"
    ],
    "web_access": [
        "timestamp", "source_ip", "http_method",
        "url_path", "status_code"
    ],
    "firewall": [
        "timestamp", "source_ip", "destination_ip",
        "destination_port", "action"
    ]
}


def load_jsonl(file_path):
    records = []

    with Path(file_path).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON at line {line_number}: {error}"
                )

    return records


def compare_fields(raw_path, processed_path, source):
    required = REQUIRED_FIELDS[source]

    raw_records = load_jsonl(raw_path)
    processed_records = load_jsonl(processed_path)

    print(f"Raw records: {len(raw_records)}")
    print(f"Processed records: {len(processed_records)}")

    failed = False

    for index, record in enumerate(processed_records, start=1):
        missing = [
            field for field in required
            if field not in record
        ]

        if missing:
            print(f"[FAIL] Record {index}: missing {missing}")
            failed = True

    if len(raw_records) != len(processed_records):
        print("[WARNING] Record counts are different.")
        failed = True

    if not failed:
        print("[PASS] Required fields are preserved.")

    return not failed


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(
            "Usage: python compare_logs.py "
            "<source> <raw.jsonl> <processed.jsonl>"
        )
        sys.exit(1)

    source, raw_path, processed_path = sys.argv[1:]

    if source not in REQUIRED_FIELDS:
        print("Source must be: linux_auth, web_access or firewall")
        sys.exit(1)

    success = compare_fields(raw_path, processed_path, source)
    sys.exit(0 if success else 1)
