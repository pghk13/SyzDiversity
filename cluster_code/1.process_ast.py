"""Normalize exported seed ASTs into a hash-indexed corpus map."""

import argparse
import json
from pathlib import Path

from ast_distance import process_program_ast


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path(__file__).resolve().parent.parent / "seed" / "AST_POC_MIXED")
    parser.add_argument("--output", type=Path, default=Path("map_AST_POC_MIXED.json"))
    args = parser.parse_args()
    if not args.input.is_dir():
        parser.error(f"AST directory does not exist: {args.input}")
    trees = {}
    for path in sorted(args.input.glob("*.json")):
        with path.open(encoding="utf-8") as stream:
            nodes, adj = process_program_ast(json.load(stream))
        trees[path.stem] = {"nodes": nodes, "adj": adj}
    if not trees:
        parser.error("no AST files found")
    args.output.write_text(json.dumps(trees, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Processed {len(trees)} ASTs into {args.output}")


if __name__ == "__main__":
    main()
