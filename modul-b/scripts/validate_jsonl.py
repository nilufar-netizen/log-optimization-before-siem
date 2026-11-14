
import json
import sys
from pathlib import Path


def validate_jsonl(file_path):
    path = Path(file_path)

    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        return False

    errors = []
    total_lines = 0

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            total_lines += 1

            try:
                json.loads(line)
            except json.JSONDecodeError as error:
                errors.append(
                    f"Line {line_number}: {error.msg}"
                )

    if errors:
        print("[FAIL] Invalid JSONL format")
        for error in errors:
            print(error)
        return False

    print("[PASS] JSONL format is valid")
    print(f"Valid records: {total_lines}")
    return True


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python validate_jsonl.py <file.jsonl>")
        sys.exit(1)

    success = validate_jsonl(sys.argv[1])
    sys.exit(0 if success else 1)

