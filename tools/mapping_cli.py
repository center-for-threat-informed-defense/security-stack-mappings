#!/usr/bin/env python3

from visualizers.visualizers_collection import VisualizersCollection
from utils.attack_data_source import AttackDataSource
from db.database import MappingDatabase
from pathlib import Path
from utils.utils import file_path, dir_path
from utils.mapping_validator import MappingValidator
import json
import yaml
import os
import argparse


class MappingCLI():

    def __init__(self):
        self.visualizers = VisualizersCollection()
        self.attack_ds = AttackDataSource()
        self.mapping_db = MappingDatabase(self.attack_ds)
        self.mapping_db.init_database()
        self.mapping_validator = MappingValidator(self.attack_ds)


    def output_attack_json(self):
        self.attack_ds.output_attack_json()
    

    def load_mapping_files(self, map_dir):
        self.mapping_files = [path for path in Path(map_dir).rglob("*.yaml")]


    def load_mapping_file(self, map_file):
        self.mapping_files = [Path(map_file)]


    def get_visualizer_names(self):
        return self.visualizers.visualizers.keys()


    def validate_mapping_files(self):
        validation_pass = True
        for mapping_file in self.mapping_files:
            with open(mapping_file, "r") as f:
                mapping_yaml = yaml.safe_load(f)

            validation_pass = validation_pass and \
                self.mapping_validator.validate_mapping(mapping_file, mapping_yaml)

        return validation_pass


    def rebuild_mappings(self):
        self.validate_mapping_files()
        # TODO:  parse mapping files and insert basic metadata about each mapping in db

    
    def visualize(self, visualizer, output_dir):
        options = {}
        options["output_dir"] = output_dir
        if output_dir:
            options["output_inline"] = False
        else:
            options["output_inline"] = True

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
        choices=['output-techniques-json', 'rebuild-mappings', 'validate', 'visualize'])
    parser.add_argument('--mapping-dir',
        help='Path to the directory containing the mapping files',
        default="../mappings", required=False, type=dir_path)
    parser.add_argument('--mapping-file',
        help='Path to the mapping file', required=False, type=file_path)
    parser.add_argument('-O', '--output', 
        help='Path to the directory were the visualizations will be written',
        required=False, type=dir_path)
    parser.add_argument('--visualizer',
        help='The name of the visualizer that will generate the visualizations',
        required=False, choices=mapping_cli.get_visualizer_names())
    parser.add_argument('--skip-validation',
        help='Skip validation when visualizing mapping(s)',
        required=False, default=False, action='store_true')

    args = parser.parse_args()

    if args.action == "visualize":
        if not args.visualizer:
            raise argparse.ArgumentTypeError(
                'Visualize action with a mapping-file specified requires the --visualizer parameter be specified')
        if args.mapping_file:
            if not args.output:
                raise argparse.ArgumentTypeError(
                    'Visualize action requires the --output parameter be specified')
        if args.mapping_file:
            mapping_cli.load_mapping_file(args.mapping_file)
        else:
            mapping_cli.load_mapping_files(args.mapping_dir)
        if not args.skip_validation:
            mapping_cli.validate_mapping_files()
        mapping_cli.visualize(args.visualizer, args.output)
    elif args.action == "rebuild-mappings":
        mapping_cli.load_mapping_files(args.mapping_dir)
        mapping_cli.rebuild_mappings()
    elif args.action == "output-techniques-json":
        mapping_cli.output_attack_json()
    elif args.action == "validate":
        if args.mapping_file:
            mapping_cli.load_mapping_file(args.mapping_file)
        else:
            mapping_cli.load_mapping_files(args.mapping_dir)
        mapping_cli.validate_mapping_files()
