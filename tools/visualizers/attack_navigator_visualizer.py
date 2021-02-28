from visualizers.base_visualizer import AbstractVisualizer
import yaml
import json
import os
import copy

class AttackNavigatorVisualizer(AbstractVisualizer):


    def __init__(self):
        super().__init__()

        with open("config/navigator_layer_template.json", "r") as f:
            self.layer_template = json.load(f)

        with open("config/navigator_layer_config.yaml", "r") as f:
            self.config = yaml.safe_load(f)


    @staticmethod
    def get_name():
        return "AttackNavigator"


    def get_output_extension(self):
        return "json"


    def get_output_folder_name(self):
        return "layers"


    def get_scores_data(self, mapping_scores):
        metadata = []
        scores = []
        category = ""
        for score in mapping_scores:
            metadata.append({"name": "category", "value": score["category"]})
            metadata.append({"name": "value", "value": score["value"]})
            metadata.append({"name": "comment", "value": score.get("comment","")})
            metadata.append({"divider": True})
            scores.append(score["value"])
            category = score["category"]

        scores.sort()
        max_score = scores[-1]
        category = category if len(scores) == 1 else "Mixed"

        return metadata, category, max_score


    def get_tech_or_sub(self, entity):
        tech = {}
        tech["techniqueID"] = entity["id"]
        tech["enabled"] = "True"
        tech["showSubtechniques"] = "True"

        metadata, category, max_score = self.get_scores_data(entity["scores"])
        tech["metadata"] = metadata

        color = self.config["score_colors"][category][max_score]
        tech["color"] = color

        return tech


    def visualize(self, mapping_files, options):
        for mapping_file in mapping_files:
            layer = copy.deepcopy(self.layer_template)
            with open(mapping_file, "r") as f:
                mapping_yaml = yaml.safe_load(f)

            layer["name"] = mapping_yaml["name"]
            layer["description"] = mapping_yaml["description"]

            for technique in mapping_yaml.get("techniques", []):
                tech = {"id": technique["id"], "scores": technique["technique-scores"]}
                tech = self.get_tech_or_sub(tech)
                layer["techniques"].append(tech)

                for sub_tech_scores in technique.get("sub-techniques-scores", []):
                    for sub_tech in sub_tech_scores.get("sub-techniques", []):
                        sub = {"id": sub_tech["id"], "scores": sub_tech_scores["scores"]}
                        sub = self.get_tech_or_sub(sub)
                        layer["techniques"].append(sub)

            self.output(options, mapping_file, json.dumps(layer, indent=4))