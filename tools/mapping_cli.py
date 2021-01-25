#!/usr/bin/env python3

from visualizers.visualizers_collection import VisualizersCollection
from utils.attack_data_source import AttackDataSource
from db.database import MappingDatabase
from pathlib import Path
from utils.validation import dir_path
import json
import yaml
import os
import argparse
import jsonschema


class MappingCLI():

    def __init__(self):
        self.visualizers = VisualizersCollection()
        self.attack_ds = AttackDataSource()
        self.mapping_db = MappingDatabase(self.attack_ds)
        self.mapping_db.init_database()

    
    def load_mapping_files(self, map_dir):
        self.mapping_files = [path for path in Path(map_dir).rglob("*.yaml") 
            if 'sample.yaml' not in path.name]


    def get_visualizer_names(self):
        return self.visualizers.visualizers.keys()


    def rebuild_mappings(self):
        with open('config/cloud_mapping_schema.json') as file_object:
            cloud_map_schema = json.load(file_object)

        for mapping_file in self.mapping_files:
            with open(mapping_file, "r") as f:
                mapping_yaml = yaml.safe_load(f)

            print(f"Validating mapping file {mapping_file} ...")
            jsonschema.validate(mapping_yaml, cloud_map_schema)

        # parse mapping files and insert basic metadata about each mapping in db

    
    def visualize(self, visualizer, output_dir):
        options = {}
        options["output_dir"] = output_dir

        visualizer = self.visualizers.visualizers[visualizer]()
        # For now visualize all mappings, later allow selecting a subset from db
        visualizer.visualize(self.mapping_files, options)


if __name__ == "__main__":
    mapping_cli = MappingCLI()
    parser = argparse.ArgumentParser(description='Validate a cloud security '
        'mapping file and output a markdown version.')
    parser.add_argument('--action',
        help='Specify the action to perform',
        required=True,
        choices=['rebuild-mappings', 'visualize'])
    parser.add_argument('--map-dir', 
        help='Path to the directory containing the mapping files',
        default="../mappings", required=False, type=dir_path)
    parser.add_argument('-O', '--output', 
        help='Path to the directory were the visualizations will be written',
        required=False, type=dir_path)
    parser.add_argument('--visualizer',
        help='The name of the visualizer that will generate the visualizations',
        required=False, choices=mapping_cli.get_visualizer_names())

    args = parser.parse_args()

    mapping_cli.load_mapping_files(args.map_dir)

    if args.action == "visualize":
        if not args.visualizer:
            raise argparse.ArgumentTypeError(
                'Visualize action requires the --visualizer parameter be specified')
        if not args.output:
            raise argparse.ArgumentTypeError(
                'Visualize action requires the --output parameter be specified')
        mapping_cli.visualize(args.visualizer, args.output)
    elif args.mode == "rebuild-mappings":
        mapping_cli.rebuild_mapping_db()