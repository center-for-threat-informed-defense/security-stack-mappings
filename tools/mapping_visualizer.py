#!/usr/bin/env python3

from visualizers.visualizers_collection import VisualizerCollection
from pathlib import Path
import json
import yaml
import os
import argparse
import jsonschema


def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise NotADirectoryError(path)


def validate_mapping_files(mapping_files):
    for mapping_file in mapping_files:
        with open(mapping_file, "r") as f:
            mapping_yaml = yaml.safe_load(f)

        print(f"Validating mapping file {mapping_file} ...")
        jsonschema.validate(mapping_yaml, cloud_map_schema)


if __name__ == "__main__":
    visualizers_col = VisualizerCollection()

    parser = argparse.ArgumentParser(description='Validate a cloud security '
        'mapping file and output a markdown version.')
    parser.add_argument('--map_dir', 
        help='Path to the directory containing the mapping files',
        default="../mappings", required=False, type=dir_path)
    parser.add_argument('-O', '--output', 
        help='Path to the directory were the visualizations will be written',
        required=True, type=dir_path)
    parser.add_argument('--visualizer',
        help='The name of the visualizer that will generate the visualizations',
        required=True, choices=visualizers_col.visualizers.keys())
    args = parser.parse_args()

    with open('config/cloud_mapping_schema.json') as file_object:
        cloud_map_schema = json.load(file_object)

    mapping_files = [path for path in Path(args.map_dir).rglob("*.yaml") 
        if 'sample.yaml' not in path.name]

    validate_mapping_files(mapping_files)

    options = {}
    options["output_dir"] = args.output

    visualizer = visualizers_col.visualizers[args.visualizer]()
    visualizer.visualize(mapping_files, options)
