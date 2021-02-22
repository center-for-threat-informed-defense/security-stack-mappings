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


    def load_tags(self):
        fn = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config/valid_tags.txt')
        with open(fn) as file_object:
            return file_object.read().splitlines()


    def verify_tags(self, mapping):
        if "tags" in mapping:
            for tag in mapping['tags']:
                if not tag in self.valid_tags:
                    print(f"Tag {tag} from mapping file {mapping['name']} is not contained within valid_tags.yaml.")
        else:
            print(f"  Warning:  Mapping file does not include any tags.")


    def verify_attack_info(self, mapping):
        techniques = mapping.get("techniques", [])
        if not techniques:
            print(f"  Error:  Mapping file does not include any techniques.")

        for technique in techniques:
            tech_id = technique['id']
            tech_name = technique['name']
            if tech_id in self.valid_techniques:
                if tech_name == self.valid_techniques[tech_id]['technique_name']:
                    if 'sub-techniques-scores' in technique:
                        for sub_techs in technique['sub-techniques-scores']:
                            for subs in sub_techs['sub-techniques']:
                                if subs['id'] not in self.valid_techniques[tech_id]["sub_techniques"]:
                                    print(f"  Error:  Sub-technique {subs['id']} - {subs['name']} is not a sub-technique"
                                        f" of {tech_id} - {tech_name}")
                                elif self.valid_techniques[tech_id]["sub_techniques"][subs['id']]['sub_technique_name'] != subs['name']:
                                    print(f"  Error:  Invalid name {subs['name']} for sub-technique subs['id'] "
                                        f", should be {self.valid_techniques[tech_id]['sub_techniques'][subs['id']]['sub_technique_id']}");
                else:
                    print(f"  Error: Technique name {tech_name} from mapping file does not match {tech_id} technique "
                        f"name {self.valid_techniques[tech_id]['technique_name']}")
            else:
                print(f"  Error: {tech_id} is not a valid ATT&CK Technique ID.")


    def verify_scores(self, mapping):
        for technique in mapping['techniques']:
            if not technique['technique-scores'] and not technique['sub-techniques-scores'][0]['scores']:
                print(f"Error: There are no scores for {technique['name']}")
                return

            if technique['technique-scores']:
                tech_scores = technique['technique-scores']
                cat_list = []
                for score in tech_scores:
                    cat_list.append(score['category'])
                    if cat_list.count(score['category']) > 1:
                        print(f"Error: There is more than one score of type {score['category']}  in "
                            f"technique-scores for {technique['name']}")
            if 'sub-techniques-scores' in technique:
                if technique['sub-techniques-scores']:
                    sub_list = []
                    for subs in technique['sub-techniques-scores']:
                        for sub_id in subs['sub-techniques']:
                            if sub_id in sub_list:
                                print(f"Error: The sub-technique {sub_id['name']} under technique {technique['name']} has been scored more than once.")
                            sub_list.append(sub_id)
                        if subs['scores']:
                            sub_scores = subs['scores']
                            cat_list = []
                            for score in sub_scores:
                                cat_list.append(score['category'])
                                if cat_list.count(score['category']) > 1:
                                    print(f"Error: There is more than one score of type {score['category']}"
                                        f" in sub-techniques-scores for {technique['name']}")
                else:
                    print(f"  Error:  Empty sub-techniques-scores object for technique {technique['name']}")


    def validate_mapping(self, mapping_file, mapping_yaml):
        if not self.valid_techniques:
            self.valid_techniques = self.attack_ds.get_techniques_and_sub_techniques()

        with open('config/cloud_mapping_schema.json') as file_object:
            cloud_map_schema = json.load(file_object)

        print(f"Validating mapping file {mapping_file} ...")
        jsonschema.validate(mapping_yaml, cloud_map_schema)

        self.verify_tags(mapping_yaml)
        self.verify_attack_info(mapping_yaml)
        self.verify_scores(mapping_yaml)