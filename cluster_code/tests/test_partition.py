import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np

from ast_distance import node_depths, process_program_ast, tree_distance, tree_similarity, weighted_nodes

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace(".", "_"), ROOT / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


similarity = load("3.2compute_similarity_matrix.py")
clustering = load("4.Louvain_clustering.py")
centroids = load("5.cluster_center_finder.py")


def tree(value):
    return {"nodes": ["ProgramAST", "test", f"*prog.ConstArg: {value}"], "adj": [[1], [2], []]}


class PartitionTests(unittest.TestCase):
    def test_schema_and_argument_values(self):
        program = {"calls": [{"name": "test", "args": [{"type": "*prog.ConstArg", "value": 3}]}]}
        self.assertEqual(process_program_ast(program), (tree(3)["nodes"], tree(3)["adj"]))
        self.assertEqual(process_program_ast(tree(3)), (tree(3)["nodes"], tree(3)["adj"]))
        self.assertEqual(tree_distance(tree(3), tree(4)), 1)
        self.assertAlmostEqual(tree_similarity(tree(3), tree(4)), 2 / 3)

    def test_cost_is_per_occurrence(self):
        value = {"nodes": ["repeat", "repeat", "repeat"], "adj": [[1], [2], []]}
        self.assertEqual([item[1] for item in weighted_nodes(value)], [1, 5, 1])
        with self.assertRaises(ValueError):
            node_depths(["root", "child"], [[1], [0]])

    def test_zero_cost_fields(self):
        left, right = tree(1), tree(2)
        left["nodes"][2] = "*prog.PointerArg: 42"
        right["nodes"][2] = "*prog.PointerArg: 82"
        self.assertEqual(tree_distance(left, right), 0)
        right["nodes"][2] = "*prog.ConstArg: AUTO"
        self.assertEqual(tree_distance(left, right), 0)

    def test_nted2_and_output_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "custom.dat")
            result, _, _ = similarity.normalize_ted_matrix(np.array([[0, 2], [2, 0]]), [3, 5], output=path)
            np.testing.assert_allclose(result, [[1, 0.6], [0.6, 1]])
            self.assertTrue(Path(path).exists())
            _, mean, variance = similarity.normalize_ted_matrix(np.zeros((1, 1)), [1], output=path)
            self.assertEqual((mean, variance), (0, 0))
            with self.assertRaises(ValueError):
                similarity.normalize_ted_matrix(np.array([[0, -1], [-1, 0]]), [1, 1], output=path)

    def test_knn_excludes_self_and_nonpositive_edges(self):
        matrix = np.array([[1, .9, 0], [.9, 1, -.1], [0, -.1, 1]])
        sparse = clustering.similarity_kNN(matrix, k=200)
        self.assertEqual(sparse.nnz, 2)
        self.assertTrue(np.all(sparse.diagonal() == 0))
        graph = clustering.similarity_to_graph(sparse)
        self.assertEqual(set(graph.nodes), {0, 1, 2})
        labels = clustering.perform_louvain_clustering(graph)
        self.assertEqual(set(labels), {0, 1, 2})
        singleton = clustering.similarity_kNN(np.ones((1, 1)), k=200)
        self.assertEqual(singleton.nnz, 0)

    def test_centroid_includes_singletons(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in [("a", 1), ("b", 2), ("c", 3)]:
                (root / f"{name}.json").write_text(json.dumps(tree(value)))
            info = root / "cluster_info.csv"
            info.write_text("ProgramHash,ClusterID\na,0\nb,0\nc,1\n")
            result = centroids.find_centers(info, root)
            self.assertEqual(result, {0: "a", 1: "c"})
            (root / "a.json").unlink()
            with self.assertRaises(FileNotFoundError):
                centroids.find_centers(info, root)


if __name__ == "__main__":
    unittest.main()
