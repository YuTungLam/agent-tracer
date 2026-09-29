"""Check generated HTML and decoded JSONL for Chinese ideographs without model calls."""

import argparse
import hashlib
import html
import json
import re
from pathlib import Path

HAN = re.compile("[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\U00020000-\U000323af]")
ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def strings(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child)
    elif isinstance(value, str):
        yield value


def audit(root: Path) -> dict:
    records, failures = [], []
    root = root.resolve()
    for directory in (root / "runs", root / "reports"):
        for path in sorted(directory.rglob("*")):
            if path.suffix not in {".html", ".jsonl"} or not path.is_file():
                continue
            if not path.resolve().is_relative_to(root):
                raise ValueError("Report resolves outside the workspace")
            raw = path.read_bytes()
            text = raw.decode("utf-8")
            bad_lines = []
            if path.suffix == ".jsonl":
                for line, content in enumerate(text.splitlines(), 1):
                    if any(HAN.search(value) for value in strings(json.loads(content))):
                        bad_lines.append(line)
            else:
                decoded = html.unescape(ESCAPE.sub(lambda match: chr(int(match[1], 16)), text))
                if HAN.search(decoded):
                    bad_lines.append(1)
            record = {
                "path": str(path.relative_to(root)),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "type": path.suffix,
                "chinese_found": bool(bad_lines),
                "affected_lines": bad_lines,
            }
            records.append(record)
            if bad_lines:
                failures.append(record["path"])
    return {
        "language": "en",
        "check": "HTML text/entities/Unicode escapes and decoded JSONL keys/string values",
        "html_files": sum(record["type"] == ".html" for record in records),
        "jsonl_files": sum(record["type"] == ".jsonl" for record in records),
        "chinese_files": failures,
        "passed": not failures,
        "files": records,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, help="Optional new JSON audit path")
    args = parser.parse_args()
    result = audit(args.root)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps({key: value for key, value in result.items() if key != "files"}, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
