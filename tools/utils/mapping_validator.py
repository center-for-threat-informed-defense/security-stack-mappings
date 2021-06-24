import os
import yaml
import json
import jsonschema
import datetime
from pathlib import Path

from utils.utils import get_project_root

class MappingValidator:

    def __init__(self, attack_ds):
        self.attack_ds = []
        self.attack_ds = attack_ds
        self.valid_techniques = {}
        self.validation_pass = True
        self.comments_found = False
        self.attack_version = None
        self.specified_tags = None
        self.tags_from_mappings = {}


    def print_validation_error(self, msg):
        self.validation_pass = False
        print(f"  Error:  {msg}")


    def print_validation_warning(self, msg):
        print(f"  Warning:  {msg}")


    def get_tags(self, mapping_files):
        for mapping_file in mapping_files:
            self.load_tags_for_mapping(mapping_file)

        return self.tags_from_mappings


    def load_specified_tags(self, tags_file):
        with open(tags_file) as file_object:
            self.specified_tags = file_object.read().splitlines()


    def load_tags_for_mapping(self, mapping_file, mapping_yaml=None):
        if self.specified_tags:
            return self.specified_tags

        platform_dir = Path(os.path.dirname(mapping_file))
        if mapping_yaml:
            platform = mapping_yaml["platform"]
        else:
            platform = platform_dir.name

        if platform in self.tags_from_mappings:
            return self.tags_from_mappings[platform]
        
        valid_tags = platform_dir / "valid_tags.txt"
        if valid_tags.exists():
            with open(valid_tags) as file_object:
                self.tags_from_mappings[platform] = file_object.read().splitlines()

        return self.tags_from_mappings.get(platform, [])


    def verify_dates(self, mapping):
        c_date = mapping.get("creation date", "03/01/2021")
        try:
            datetime.datetime.strptime(c_date, '%m/%d/%Y')
        except ValueError:
            self.print_validation_error(f"The creation date field, '{c_date}' must be formatted as mm/dd/yyyy")

        l_date = mapping.get("last update", "03/01/2021")
        try:
            datetime.datetime.strptime(l_date, '%m/%d/%Y')
        except ValueError:
            self.print_validation_error(f"The last update field, '{l_date}' must be formatted as mm/dd/yyyy")


    def is_tag_valid(self, tag, platform):
        if self.specified_tags:
            return tag in self.specified_tags
        else:
            return tag in self.tags_from_mappings.get(platform, [])


    def verify_tags(self, mapping):
        if "tags" in mapping:
            # this if check is here because we don't want to emit a warning in this case
            # If the tags element is present but empty, then the assumption is that the 
            # author explicitly excluded tags.
            if mapping["tags"]:
                for tag in mapping['tags']:
                    if not self.is_tag_valid(tag, mapping['platform']):
                        self.print_validation_error(f"Tag '{tag}' from mapping file {mapping['name']} "
                            "is not contained within valid_tags.yaml.")
        else:
            self.print_validation_warning(f"Mapping file does not include any tags.")


    def verify_references(self, mapping):
        if len(mapping.get("references", [])) == 0:
            self.print_validation_warning(f"Mapping file does not include any references, "
                "it is recommended to add at least the URL for the control documentation.")
        for reference in mapping.get("references", []):
            if not reference:
                self.print_validation_error(f"References section contains an empty reference")



    def verify_attack_info(self, mapping):
        techniques = mapping.get("techniques", [])
        if not techniques:
            self.print_validation_warning(f"Mapping file does not include any techniques.")

        for technique in techniques:
            tech_id = technique['id']
            tech_name = technique['name']
            if tech_id in self.valid_techniques:
                if tech_name == self.valid_techniques[tech_id]['technique_name']:
                    if 'sub-techniques-scores' in technique:
                        for sub_techs in technique['sub-techniques-scores']:
                            for subs in sub_techs['sub-techniques']:
                                if subs['id'] not in self.valid_techniques[tech_id]["sub_techniques"]:
                                    self.print_validation_error(f"Sub-technique {subs['id']} - {subs['name']} "
                                        f"is not a sub-technique of {tech_id} - {tech_name}")
                                elif self.valid_techniques[tech_id]["sub_techniques"][subs['id']]['sub_technique_name'] != subs['name']:
                                    self.print_validation_error(f"Invalid name, {subs['name']}, for sub-technique {subs['id']}"
                                        f", should be {self.valid_techniques[tech_id]['sub_techniques'][subs['id']]['sub_technique_name']}");
                else:
                    self.print_validation_error(f"Technique name {tech_name} from mapping file does not match {tech_id} "
                        f"technique name {self.valid_techniques[tech_id]['technique_name']}")
            else:
                self.print_validation_error(f"{tech_id} is not a valid ATT&CK Technique ID.")


    def verify_scores(self, mapping):
        for technique in mapping.get('techniques', []):
            if not technique['technique-scores'] and not technique['sub-techniques-scores'][0]['scores']:
                self.print_validation_error(f"There are no scores for {technique['name']}")
                return

            if technique['technique-scores']:
                tech_scores = technique['technique-scores']
                cat_list = []
                for score in tech_scores:
                    cat_list.append(score['category'])
                    if cat_list.count(score['category']) > 1:
                        self.print_validation_error(f"There is more than one score of type {score['category']}  in "
                            f"technique-scores for {technique['name']}")
                    
                    if score.get("comments", ""):
                        self.comments_found = True
            if 'sub-techniques-scores' in technique:
                if technique['sub-techniques-scores']:
                    sub_list = []
                    for subs in technique['sub-techniques-scores']:
                        if not len(subs.get('sub-techniques', [])):
                            self.print_validation_error(f"Empty sub-technique list for sub-techniques-scores object " 
                                f"for technique {technique['name']}")

                        for sub_id in subs['sub-techniques']:
                            if sub_id in sub_list:
                                self.print_validation_error(f"The sub-technique {sub_id['name']} under "
                                    f"technique {technique['name']} has been scored more than once.")
                            sub_list.append(sub_id)

                        if not len(subs.get('scores', [])):
                            self.print_validation_error(f"Empty scores list for sub-techniques-scores object " 
                                f"for technique {technique['name']}")
                        if subs['scores']:
                            sub_scores = subs['scores']
                            cat_list = []
                            for score in sub_scores:
                                cat_list.append(score['category'])
                                if cat_list.count(score['category']) > 1:
                                    self.print_validation_error(f"There is more than one score of type {score['category']}"
                                        f" in sub-techniques-scores for {technique['name']}")
                                if score.get("comments", ""):
                                    self.comments_found = True
                else:
                    self.print_validation_error(f"Empty sub-techniques-scores object for technique {technique['name']}")


    def validate_only_ascii(self, mapping_file):
        with open(mapping_file) as fp:
            line_no = 0
            for line in fp.readlines():
                line_no += 1
                if not line.isascii():
                    self.print_validation_warning(f"Mapping file contains non-ascii characters:  {line_no}:  {line}")


    def validate_mapping(self, mapping_file, mapping_yaml):
        self.validation_pass = True
        self.comments_found = False
        if self.attack_version != mapping_yaml["ATT&CK version"]:
            self.attack_version = mapping_yaml["ATT&CK version"]
            self.valid_techniques = self.attack_ds.get_techniques_and_sub_techniques(True, self.attack_version)

        root_dir = get_project_root()
        with open(f'{root_dir}/tools/config/mapping_schema.json') as file_object:
            mapping_schema = json.load(file_object)

        print(f"Validating mapping file {mapping_file} ...")
        if mapping_file.name.endswith(".yml"):
            self.print_validation_warning(f"Mapping file extension yaml is preferable to yml.")

        jsonschema.validate(mapping_yaml, mapping_schema)

        self.validate_only_ascii(mapping_file)
        self.verify_dates(mapping_yaml)
        self.load_tags_for_mapping(mapping_file, mapping_yaml)
        self.verify_tags(mapping_yaml)
        self.verify_references(mapping_yaml)
        self.verify_attack_info(mapping_yaml)
        self.verify_scores(mapping_yaml)

        if mapping_yaml.get("comments", ""):
            self.comments_found = True

        if not self.comments_found:
            self.print_validation_warning(f"This mapping file does not contain any comments explaining scoring."
                "  Adding comments to score objects enriches the value of mappings.")

        return self.validation_pass