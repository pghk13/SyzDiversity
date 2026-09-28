"""Normalize TED using Eq. 2: similarity = 1 - TED / max(node counts)."""

import argparse
import pickle

import numpy as np


def get_node_counts(trees):
    return [len(tree["nodes"]) for tree in trees]


def normalize_ted_matrix(ted_matrix, node_counts, method="NTED2", output=None):
    counts = np.asarray(node_counts, dtype=np.float64)
    count = len(counts)
    if count == 0 or np.any(counts <= 0) or ted_matrix.shape != (count, count):
        raise ValueError("expected a nonempty square matrix and positive node counts")
    if method not in ("NTED1", "NTED2"):
        raise ValueError("use NTED2 for the paper, or NTED1 for sum-normalized ablation")
    path = output or f"similarity_matrix_{method}.dat"
    similarity = np.memmap(path, dtype="float32", mode="w+", shape=(count, count))
    total, squares, pairs = 0.0, 0.0, 0
    for i in range(count):
        row = np.asarray(ted_matrix[i], dtype=np.float64)
        if not np.all(np.isfinite(row)) or np.any(row < 0):
            raise ValueError(f"incomplete or invalid distances in row {i}")
        denominator = np.maximum(counts[i], counts) if method == "NTED2" else counts[i] + counts
        values = 1.0 - row / denominator
        # Weighted costs can exceed node count. Keep Eq. 2 here; graph creation
        # discards nonpositive edges instead of treating them as similarities.
        similarity[i] = values
        upper = values[i + 1:]
        total += upper.sum()
        squares += np.square(upper).sum()
        pairs += len(upper)
    similarity.flush()
    mean = total / pairs if pairs else 0.0
    variance = max(0.0, squares / pairs - mean * mean) if pairs else 0.0
    return similarity, mean, variance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trees", "--trees_pickle", default="trees_AST_POC_MIXED.pkl")
    parser.add_argument("--distance_matrix", default="cost5-distance_matrix_POC_MIXED.dat")
    parser.add_argument("--method", choices=("NTED1", "NTED2"), default="NTED2")
    parser.add_argument("--similarity_output")
    args = parser.parse_args()
    with open(args.trees, "rb") as stream:
        trees = pickle.load(stream)
    count = len(trees)
    matrix = np.memmap(args.distance_matrix, dtype="float32", mode="r", shape=(count, count))
    _, mean, variance = normalize_ted_matrix(matrix, get_node_counts(trees), args.method, args.similarity_output)
    print(f"Pairwise similarity: mean={mean:.6f}, variance={variance:.6f}")


if __name__ == "__main__":
    main()
