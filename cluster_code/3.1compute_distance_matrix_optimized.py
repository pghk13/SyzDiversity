"""Compute the symmetric weighted TED matrix without materializing all pairs."""

import argparse
import itertools
import os
import pickle

import numpy as np
from joblib import Parallel, delayed
from tqdm import tqdm

from ast_distance import DEFAULT_SYSCALL_COST, tree_distance


def compute_distance(pair, trees, syscall_cost=DEFAULT_SYSCALL_COST):
    i, j = pair
    return i, j, tree_distance(trees[i], trees[j], syscall_cost)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trees", default="trees_AST_POC_MIXED.pkl")
    parser.add_argument("--output", default="cost5-distance_matrix_POC_MIXED.dat")
    parser.add_argument("--syscall-cost", type=int, default=DEFAULT_SYSCALL_COST)
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    parser.add_argument("--chunk-size", type=int, default=4096)
    args = parser.parse_args()
    if args.syscall_cost < 1 or args.jobs < 1 or args.chunk_size < 1:
        parser.error("cost, jobs and chunk size must be positive")
    with open(args.trees, "rb") as stream:
        trees = pickle.load(stream)
    count = len(trees)
    if not count:
        parser.error("the corpus is empty")
    matrix = np.memmap(args.output, dtype="float32", mode="w+", shape=(count, count))
    # Incomplete runs are distinguishable from a valid zero distance.
    matrix[:] = np.nan
    np.fill_diagonal(matrix, 0)
    pairs = itertools.combinations(range(count), 2)
    with Parallel(n_jobs=args.jobs) as workers, tqdm(total=count * (count - 1) // 2) as progress:
        while True:
            chunk = list(itertools.islice(pairs, args.chunk_size))
            if not chunk:
                break
            for i, j, distance in workers(delayed(compute_distance)(pair, trees, args.syscall_cost) for pair in chunk):
                matrix[i, j] = matrix[j, i] = distance
            matrix.flush()
            progress.update(len(chunk))


if __name__ == "__main__":
    main()
