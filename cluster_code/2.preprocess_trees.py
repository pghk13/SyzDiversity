# preprocess_trees.py
# Responsible for loading AST data and converting it to list format
# and saving the result as a binary pickle file for subsequent processing or analysis.
# Input: map.json file
# Output: trees.pkl file

import os
import argparse
import json
import pickle


def load_trees(map_file_path):
    """
    Load AST tree data and convert to list.

    Args:
    map_file_path (str): Path to the map.json file.

    Returns:
    list: Tree data list arranged in index order.
    """
    with open(map_file_path, "r", encoding="utf-8") as file:
        ast_map = json.load(file)
    filenames = sorted(ast_map.keys())  # Sort to ensure consistency
    trees_list = [ast_map[fname] for fname in filenames]
    return filenames, trees_list


def save_trees_pickle(trees_list, output_pickle_path):
    """
    Save tree data list as pickle file.

    Args:
    trees_list (list): Tree data list.
    output_pickle_path (str): Output pickle file path.
    """
    with open(output_pickle_path, "wb") as f:
        pickle.dump(trees_list, f)


def main():
    parser = argparse.ArgumentParser(description="Prepare ordered ASTs for pairwise distance calculation")
    parser.add_argument("--input", default="map_AST_POC_MIXED.json")
    parser.add_argument("--output", default="trees_AST_POC_MIXED.pkl")
    args = parser.parse_args()
    map_file, output_pickle = args.input, args.output

    if not os.path.isfile(map_file):
        print(f"File '{map_file}' does not exist. Please ensure 'map.json' file is in the current directory.")
        return

    print("Loading and converting tree data...")
    filenames, trees_list = load_trees(map_file)
    print(f"Loaded {len(trees_list)} AST trees.")

    print(f"Saving tree data to '{output_pickle}'...")
    save_trees_pickle(trees_list, output_pickle)
    print("Tree data saving completed.")


if __name__ == "__main__":
    main()
