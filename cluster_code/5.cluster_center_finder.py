"""Choose a fixed medoid for every community, including singleton communities."""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
from joblib import Parallel, delayed

from ast_distance import DEFAULT_SYSCALL_COST, process_program_ast, tree_similarity


def load_ast(path):
    with open(path, encoding="utf-8") as stream:
        nodes, adj = process_program_ast(json.load(stream))
    return {"nodes": nodes, "adj": adj}


def choose_center(hashes, ast_dir, syscall_cost=DEFAULT_SYSCALL_COST):
    hashes = sorted(set(hashes))
    trees = [load_ast(Path(ast_dir) / f"{seed}.json") for seed in hashes]
    totals = np.zeros(len(hashes))
    for i, left in enumerate(trees):
        for j in range(i + 1, len(trees)):
            distance = 1.0 - tree_similarity(left, trees[j], syscall_cost)
            totals[i] += distance
            totals[j] += distance
    # Sorted hashes make medoid ties reproducible.
    return hashes[int(np.argmin(totals))]


def find_centers(cluster_info, ast_dir, syscall_cost=DEFAULT_SYSCALL_COST, jobs=1):
    communities = defaultdict(list)
    membership = {}
    with open(cluster_info, newline="", encoding="utf-8") as stream:
        reader = csv.reader(stream)
        next(reader)
        for row in reader:
            seed, community = row[0], int(row[1])
            if seed in membership and membership[seed] != community:
                raise ValueError(f"conflicting community for {seed}")
            membership[seed] = community
            communities[community].append(seed)
    ids = sorted(communities)
    centers = Parallel(n_jobs=jobs)(delayed(choose_center)(communities[cid], ast_dir, syscall_cost) for cid in ids)
    return dict(zip(ids, centers))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-info", default="cluster_info.csv")
    parser.add_argument("--ast-dir", required=True)
    parser.add_argument("--output", default="cluster_core.csv")
    parser.add_argument("--syscall-cost", type=int, default=DEFAULT_SYSCALL_COST)
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args()
    centers = find_centers(args.cluster_info, args.ast_dir, args.syscall_cost, args.jobs)
    with open(args.output, "w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["ClusterID", "SeedHash"])
        writer.writerows(centers.items())


if __name__ == "__main__":
    main()
