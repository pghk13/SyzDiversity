# Louvain_V2.py

import numpy as np
from tqdm import tqdm
import networkx as nx
import community as community_louvain
import argparse
import json
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib import colormaps
from scipy.sparse import csr_matrix
import time


def load_filenames(map_file_path):
    """Load map.json file and return sorted filename list."""
    with open(map_file_path, "r", encoding="utf-8") as file:
        ast_map = json.load(file)
    filenames = sorted(ast_map.keys())
    return filenames


def load_similarity_matrix(mmap_path, num_trees):
    """
    Load similarity matrix and ensure its symmetry and diagonal of 1.

    Args:
        mmap_path (str): Memory-mapped file path of similarity matrix.
        num_trees (int): Number of trees, used to define matrix shape.

    Returns:
        numpy.ndarray: Processed similarity matrix.
    """
    dtype = 'float32'
    try:
        memmap_similarity = np.memmap(mmap_path, dtype=dtype, mode='r', shape=(num_trees, num_trees))
    except ValueError as e:
        raise ValueError(f"Unable to load memmap file: {e}")

    if not np.isfinite(memmap_similarity).all():
        raise ValueError("similarity matrix contains non-finite entries")

    # Ensure similarity matrix is symmetric and diagonal is 1
    print("Fixing symmetry and diagonal of similarity matrix...")
    similarity_matrix = (memmap_similarity + memmap_similarity.T) / 2
    np.fill_diagonal(similarity_matrix, 1.0)
    similarity_matrix = np.clip(similarity_matrix, 0, 1)
    print("Similarity matrix fixing completed.")

    del memmap_similarity
    return similarity_matrix


def similarity_kNN(S, k=200):
    """
    Convert similarity matrix to sparse representation based on k-NN method, ensuring each node's nearest neighbors do not include itself.

    Args:
        S (numpy.ndarray): Similarity matrix.
        k (int): Number of nearest neighbors to keep for each node.

    Returns:
        csr_matrix: Sparse similarity matrix.
    """
    n = S.shape[0]
    if k < 0:
        raise ValueError("k must be nonnegative")
    k = min(k, max(0, n - 1))

    # Create a temporary matrix, set diagonal to -inf to exclude self
    S_temp = S.copy()
    np.fill_diagonal(S_temp, -np.inf)

    # Keep k largest similarity values for each row (excluding self)
    # Use argsort to sort each row in descending order and select top k indices
    indices = np.argsort(-S_temp, axis=1)[:, :k]

    data = []
    row = []
    col = []

    for i in tqdm(range(n), desc="Selecting k nearest neighbors"):
        for j in indices[i]:
            if not np.isfinite(S[i, j]) or S[i, j] <= 0:
                continue
            row.append(i)
            col.append(j)
            data.append(S[i, j])

    # Build sparse similarity matrix
    S_sparse = csr_matrix((data, (row, col)), shape=(n, n))

    # Symmetrize similarity matrix
    S_sparse = S_sparse.maximum(S_sparse.transpose())

    # Add statistics
    if S_sparse.data.size > 0:
        print("Minimum value of similarity matrix:", S_sparse.data.min())
        print("Maximum value of similarity matrix:", S_sparse.data.max())
        print("Mean value of similarity matrix:", S_sparse.data.mean())
    else:
        print("Sparse similarity matrix is empty.")

    return S_sparse


def similarity_threshold(S, threshold=0.5):
    """
    Build sparse similarity matrix based on similarity threshold.

    Args:
        S (numpy.ndarray): Similarity matrix.
        threshold (float): Similarity threshold, only edges with similarity > threshold will be kept.

    Returns:
        csr_matrix: Sparse similarity matrix.
    """
    S_sparse = csr_matrix(S)

    # Keep edges with similarity greater than threshold
    S_sparse.data[S_sparse.data <= threshold] = 0
    S_sparse.eliminate_zeros()

    # Symmetrize similarity matrix
    S_sparse = S_sparse.maximum(S_sparse.transpose())

    # Add statistics
    print("Minimum value of similarity matrix:", S_sparse.data.min())
    print("Maximum value of similarity matrix:", S_sparse.data.max())
    print("Mean value of similarity matrix:", S_sparse.data.mean())

    return S_sparse


def similarity_to_graph(S_sparse):
    """
    Build NetworkX graph directly from sparse similarity matrix.

    Args:
        S_sparse (scipy.sparse.csr_matrix): Sparse similarity matrix.

    Returns:
        networkx.Graph: Built graph.
    """
    try:
        G = nx.from_scipy_sparse_array(S_sparse, edge_attribute='weight')
    except AttributeError:
        print("NetworkX version does not support 'from_scipy_sparse_matrix', trying 'from_scipy_sparse_array'.")
        G = nx.from_scipy_sparse_array(S_sparse, edge_attribute='weight')
    except Exception as e:
        print(f"Error occurred when building graph with NetworkX: {e}")
        sys.exit(1)

    # Check connectivity
    num_cc = nx.number_connected_components(G)
    largest_cc = max(nx.connected_components(G), key=len)
    print(f"Number of connected components in graph: {num_cc}")
    print(f"Size of largest connected component: {len(largest_cc)}")
    return G


def perform_louvain_clustering(G, resolution=1.0, max_clusters=None):
    """
    Perform community detection using Louvain algorithm.

    Args:
        G (networkx.Graph): Graph to be clustered.
        resolution (float): Resolution parameter of Louvain algorithm, controlling clustering granularity.
        max_clusters (int, optional): Maximum allowed number of clusters. If specified, the algorithm will try to adjust resolution to meet this limit.

    Returns:
        dict: Mapping from nodes to communities.
    """
    print("Performing community detection using Louvain algorithm...")
    if max_clusters is None:
        partition = community_louvain.best_partition(G, weight='weight', resolution=resolution, random_state=0)
    else:
        current_resolution = resolution
        step = 0.1
        max_resolution = 10.0
        partition = community_louvain.best_partition(G, weight='weight', resolution=current_resolution, random_state=0)
        num_clusters = len(set(partition.values()))
        iteration = 0
        max_iterations = 100

        while num_clusters > max_clusters and iteration < max_iterations:
            current_resolution += step
            if current_resolution > max_resolution:
                print(f"Reached maximum resolution {max_resolution}, cannot further reduce cluster count.")
                break
            partition = community_louvain.best_partition(G, weight='weight', resolution=current_resolution, random_state=0)
            num_clusters = len(set(partition.values()))
            iteration += 1
            print(f"Iteration {iteration}: Current resolution={current_resolution:.2f}, cluster count={num_clusters}")

        if num_clusters > max_clusters:
            print(f"Warning: Unable to reduce cluster count to {max_clusters} within maximum iterations. Current cluster count is {num_clusters}.")
        else:
            print(f"Successfully reduced cluster count to {num_clusters}, using resolution={current_resolution:.2f}")

    print(f"Louvain clustering completed. Total cluster count: {len(set(partition.values()))}")
    return partition


def partition_to_labels(partition, num_nodes):
    """Convert clustering results to label array."""
    labels = np.zeros(num_nodes, dtype=int)
    for node, community in partition.items():
        labels[node] = community
    return labels


def save_cluster_labels(labels, filenames, output_npy_path, output_csv_path):
    """Save cluster labels as .npy and .csv files."""
    np.save(output_npy_path, labels)
    print(f"Cluster labels saved to '{output_npy_path}'")

    df = pd.DataFrame({
        'Filename': filenames,
        'Cluster': labels
    })
    df.to_csv(output_csv_path, index=False)
    print(f"Clustering results saved as CSV file '{output_csv_path}'")


def visualize_clusters(G, partition, output_image_path):
    """
    Visualize graph based on clustering results.

    Args:
        G (networkx.Graph): Graph to be visualized.
        partition (dict): Mapping from nodes to communities.
        output_image_path (str): Path to save the image.
    """
    print("Performing graph visualization...")
    pos = nx.spring_layout(G, seed=42)  # Fixed layout for reproducibility
    cmap = colormaps.get_cmap('tab20')  # Use discrete colormap 'tab20'

    # Get community labels for nodes
    labels = list(partition.values())
    num_nodes = len(G.nodes)  # Number of nodes

    # Verify consistency between node count and label count
    if len(labels) != num_nodes:
        raise ValueError(f"Node count ({num_nodes}) and cluster label count ({len(labels)}) are inconsistent!")

    plt.figure(figsize=(20, 12))

    # Draw nodes and get return value
    nodes = nx.draw_networkx_nodes(
        G, pos,
        node_size=50,
        node_color=labels,  # Directly pass color labels for all nodes
        cmap=cmap,
        vmin=min(labels),
        vmax=max(labels),
        alpha=0.7
    )

    # Draw edges
    nx.draw_networkx_edges(G, pos, alpha=0.3, width=0.5)

    plt.title(f"Graph Clustering Visualization (Total {len(set(labels))} Clusters)", fontsize=16)
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Visualization saved to '{output_image_path}'")


def main():
    start_time = time.time()

    parser = argparse.ArgumentParser(description="Perform Louvain clustering on similarity matrix.")
    parser.add_argument("--map_file", type=str, default="map_AST_POC_MIXED.json",
                        help="Path to map.json file containing filename mappings")
    parser.add_argument("--similarity_matrix", type=str, default="similarity_matrix_NTED2.dat",
                        help="Path to similarity matrix memmap file")
    parser.add_argument("--method", type=str, choices=['knn', 'threshold'], default='knn',
                        help="Method to build graph: 'knn' or 'threshold'")
    parser.add_argument("--k", type=int, default=200,
                        help="Number of nearest neighbors for knn method (default: 200)")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="Similarity threshold for threshold method (default: 0.5)")
    parser.add_argument("--resolution", type=float, default=1.0,
                        help="Resolution parameter for Louvain algorithm (default: 1.0)")
    parser.add_argument("--max_clusters", type=int, default=None,
                        help="Maximum number of clusters (optional)")
    parser.add_argument("--output_csv", type=str, default=None,
                        help="Output CSV file path")
    parser.add_argument("--output_npy", type=str, default=None,
                        help="Output NPY file path")
    parser.add_argument("--output_image", type=str, default=None,
                        help="Output image file path for visualization")
    parser.add_argument("--visualize", action='store_true',
                        help="Enable visualization")

    args = parser.parse_args()

    # Load filename mappings
    print("Loading filename mappings...")
    filenames = load_filenames(args.map_file)
    num_trees = len(filenames)
    print(f"Loaded {num_trees} filenames.")

    # Load similarity matrix
    print("Loading similarity matrix...")
    similarity_matrix = load_similarity_matrix(args.similarity_matrix, num_trees)
    print("Similarity matrix loaded.")

    # Build sparse similarity matrix
    print(f"Building sparse similarity matrix using {args.method} method...")
    if args.method == 'knn':
        S_sparse = similarity_kNN(similarity_matrix, k=args.k)
        graph_method_str = f"knn_k{args.k}"
    elif args.method == 'threshold':
        S_sparse = similarity_threshold(similarity_matrix, threshold=args.threshold)
        graph_method_str = f"threshold_{args.threshold}"

    print(f"Sparse similarity matrix built. Non-zero elements: {S_sparse.nnz}")

    # Build graph
    print("Building graph...")
    G = similarity_to_graph(S_sparse)
    print(f"Graph built. Nodes: {G.number_of_nodes()}, Edges: {G.number_of_edges()}")

    # Perform Louvain clustering
    partition = perform_louvain_clustering(G, resolution=args.resolution, max_clusters=args.max_clusters)

    # Convert to label array
    labels = partition_to_labels(partition, num_trees)

    # Generate output filenames
    base_name = f"louvain_cluster_labels_{os.path.splitext(os.path.basename(args.similarity_matrix))[0]}_{graph_method_str}_res{args.resolution}"
    if args.max_clusters:
        base_name += f"_max{args.max_clusters}"

    output_csv = args.output_csv or f"{base_name}.csv"
    output_npy = args.output_npy or f"{base_name}.npy"
    output_image = args.output_image or f"{base_name}_visualization.png"

    # Save results
    save_cluster_labels(labels, filenames, output_npy, output_csv)

    # Statistics
    unique_clusters = np.unique(labels)
    cluster_sizes = [np.sum(labels == cluster) for cluster in unique_clusters]
    print(f"Total clusters: {len(unique_clusters)}")
    print(f"Cluster size range: {min(cluster_sizes)} - {max(cluster_sizes)}")
    print(f"Average cluster size: {np.mean(cluster_sizes):.2f}")

    # Visualization
    if args.visualize:
        print("Generating visualization...")
        visualize_clusters(G, partition, output_image)

    end_time = time.time()
    print(f"Total runtime: {end_time - start_time:.2f} seconds")
    print("Clustering completed!")


if __name__ == "__main__":
    main()
