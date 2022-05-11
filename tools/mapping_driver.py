from visualizers.visualizers_collection import VisualizersCollection
from utils.attack_data_source import AttackDataSource
from db.database import MappingDatabase
from pathlib import Path
from utils.mapping_validator import MappingValidator
import yaml
from yaml.scanner import ScannerError
import os

class MappingDriver():


    def __init__(self):
        self.visualizers = VisualizersCollection()
        self.attack_ds = AttackDataSource()
        self.mapping_validator = MappingValidator(self.attack_ds)


    def output_attack_json(self):
        self.attack_ds.output_attack_json()


    def set_mapping_db(self, db_file):
        self.mapping_db = MappingDatabase(self.attack_ds, db_file)


    def query_mapping_files(self, tags, relationship, control_names, platforms):
        return self.mapping_db.query_mapping_files(tags, relationship, control_names, platforms)


    def query_mapping_file_scores(self, categories, attack_ids, controls, level, platforms, scores, tactics, tags):
        return self.mapping_db.query_mapping_file_scores(categories, attack_ids, controls, \
            level, platforms, scores, tactics, tags)


    def load_mapping_files_as_unit(self, map_files):
        paths = []
        for map_file in map_files:
            paths.append(Path(map_file))

        self.mapping_files = [paths]


    def load_mapping_dir(self, map_dir, no_recurse=False):
        if no_recurse:
            self.mapping_files = [path for path in Path(map_dir).glob("*.yaml")]
            self.mapping_files.extend([path for path in Path(map_dir).glob("*.yml")])
        else:
            self.mapping_files = [path for path in Path(map_dir).rglob("*.yaml")]
            self.mapping_files.extend([path for path in Path(map_dir).rglob("*.yml")])


    def load_mapping_file(self, map_file):
        self.mapping_files = [Path(map_file)]


    def load_specified_tags(self, tags_file):
        self.mapping_validator.load_specified_tags(tags_file)


    def get_visualizer_names(self):
        return self.visualizers.visualizers.keys()


    def __validate_mapping_files(self, mapping_files):
        validation_pass = True
        for mapping_file in mapping_files:

            # mapping files as a unit, e.g. tag
            if type(mapping_file) is list:
                validation_pass = validation_pass and \
                    self.__validate_mapping_files(mapping_file)
            else:
                with open(mapping_file, "r") as f:
                    try:
                        mapping_yaml = yaml.safe_load(f)
                    except ScannerError as se:
                        validation_pass = False
                        print(f"  Error:  Invalid YAML Syntax - {se.problem}{se.problem_mark}")

                if "ATT&CK version" in mapping_yaml and "platform" in mapping_yaml:
                    validation_pass = validation_pass and \
                        self.mapping_validator.validate_mapping(mapping_file, mapping_yaml)
                else:
                    print(f"Skipping {mapping_file}, not a mapping file")

        return validation_pass


    def validate_mapping_files(self):
        return self.__validate_mapping_files(self.mapping_files)


    def rebuild_mappings(self, skip_validation, skip_attack):
        if skip_validation or self.validate_mapping_files():
            tags = self.mapping_validator.get_tags(self.mapping_files)
            self.mapping_db.init_database(self.mapping_files, tags, skip_attack)


    def visualize(self, visualizer, output_dir, options={}):
        options["output_dir"] = output_dir
        if output_dir:
            options["output_inline"] = False
        else:
            options["output_inline"] = True

        visualizer = self.visualizers.visualizers[visualizer]()
        # For now visualize all mappings, later allow selecting a subset from db
        visualizer.visualize(self.mapping_files, options)

