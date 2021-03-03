import os
import yaml
import json
import jsonschema

class MappingValidator:

    def __init__(self, attack_ds):
        self.valid_tags = self.load_tags()
        self.attack_ds = []
        self.attack_ds = attack_ds
        self.valid_techniques = {}
        self.validation_pass = True


    def print_validation_error(self, msg):
        self.validation_pass = False
        print(f"  Error:  {msg}")


    def print_validation_warning(self, msg):
        print(f"  Warning:  {msg}")


    def load_tags(self):
        fn = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config/valid_tags.txt')
        with open(fn) as file_object:
            return file_object.read().splitlines()


    def verify_tags(self, mapping):
        if "tags" in mapping:
            for tag in mapping['tags']:
                if not tag in self.valid_tags:
                    self.print_validation_error(f"Tag {tag} from mapping file {mapping['name']} "
                        "is not contained within valid_tags.yaml.")
        else:
            self.print_validation_warning(f"Mapping file does not include any tags.")


    def verify_references(self, mapping):
        if len(mapping.get("references", [])) == 0:
            self.print_validation_warning(f"Mapping file does not include any references, "
                "it is recommended to add at least the URL for the control documentation.")


    def verify_attack_info(self, mapping):
        techniques = mapping.get("techniques", [])
        if not techniques:
            self.print_validation_error(f"Mapping file does not include any techniques.")

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
        for technique in mapping['techniques']:
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
            if 'sub-techniques-scores' in technique:
                if technique['sub-techniques-scores']:
                    sub_list = []
                    for subs in technique['sub-techniques-scores']:
                        for sub_id in subs['sub-techniques']:
                            if sub_id in sub_list:
                                self.print_validation_error(f"The sub-technique {sub_id['name']} under "
                                    f"technique {technique['name']} has been scored more than once.")
                            sub_list.append(sub_id)
                        if subs['scores']:
                            sub_scores = subs['scores']
                            cat_list = []
                            for score in sub_scores:
                                cat_list.append(score['category'])
                                if cat_list.count(score['category']) > 1:
                                    self.print_validation_error(f"There is more than one score of type {score['category']}"
                                        f" in sub-techniques-scores for {technique['name']}")
                else:
                    self.print_validation_error(f"Empty sub-techniques-scores object for technique {technique['name']}")


    def validate_mapping(self, mapping_file, mapping_yaml):
        self.validation_pass = True
        if not self.valid_techniques:
            self.valid_techniques = self.attack_ds.get_techniques_and_sub_techniques()

        with open('config/mapping_schema.json') as file_object:
            mapping_schema = json.load(file_object)

        print(f"Validating mapping file {mapping_file} ...")
        jsonschema.validate(mapping_yaml, mapping_schema)

        self.verify_tags(mapping_yaml)
        self.verify_references(mapping_yaml)
        self.verify_attack_info(mapping_yaml)
        self.verify_scores(mapping_yaml)

        return self.validation_pass