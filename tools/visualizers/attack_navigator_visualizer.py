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

        self.legend = []


    @staticmethod
    def get_name():
        return "AttackNavigator"


    def get_output_extension(self):
        return "json"


    def get_output_folder_name(self):
        return "layers"


    def get_legend(self):
        if self.legend:
            return self.legend
        
        for category, score_color  in self.config["score_colors"].items():
            for score, color in score_color.items():
                self.legend.append({"label": f"{category} - {score}", "color":color})
        
        return self.legend


    def get_scores_data(self, mapping_scores):
        metadata = []
        scores = []
        category = ""
        for score in mapping_scores:
            metadata.append({"name": "category", "value": score["category"]})
            metadata.append({"name": "value", "value": score["value"]})
            metadata.append({"name": "comment", "value": score.get("comments","")})
            metadata.append({"divider": True})
            scores.append(score["value"])
            category = score["category"]

        metadata = metadata[:-1]
        scores.sort()
        max_score = scores[-1]
        category = category if len(scores) == 1 else "Mixed"

        return metadata, category, max_score


    def get_tech_or_sub(self, entity, mapping_yaml, unit_mode):
        tech = {}
        tech["techniqueID"] = entity["id"]
        tech["enabled"] = "True"
        tech["showSubtechniques"] = "True"

        metadata, category, max_score = self.get_scores_data(entity["scores"])
        tech["metadata"] = metadata
        if unit_mode:
            tech["metadata"].insert(0, {"name": "control", "value": mapping_yaml["name"]})

        color = self.config["score_colors"][category][max_score]
        tech["color"] = color
        tech["score"] = max_score
        tech["category"] = category

        return tech


    def add_technique_or_sub(self, techniques, entity):
        entity_id = entity["techniqueID"]
        if entity_id in techniques:
            existing = techniques[entity_id]
            existing["metadata"].append({"divider": True})
            existing["metadata"].extend(entity["metadata"])

            if existing["category"] != entity["category"]:
                existing["category"] = "Mixed"
                max_score = [existing["score"], entity["score"]].sort()
                max_score = max_score[-1]
                color = self.config["score_colors"][existing["category"]][max_score]
                existing["color"] = color
        else:
            techniques[entity_id] = entity


    def visualize(self, mapping_files, options):
        for mapping_file in mapping_files:
            layer = copy.deepcopy(self.layer_template)
            techniques = {}

            # mapping_file can actually be a list of files, e.g. mapping files that share a tag
            m_files, unit_mode = (mapping_file, True) if type(mapping_file) is list else ([mapping_file], False)

            if unit_mode:
                options["output_filename"] = options["title"].replace(" ", "_")
                layer["name"] = options["title"]
                layer["description"] = options["description"]

            names = []
            for mapping_file in m_files:
                with open(mapping_file, "r") as f:
                    mapping_yaml = yaml.safe_load(f)

                names.append(mapping_yaml["name"])
                if not unit_mode:
                    layer["name"] = mapping_yaml["name"]
                    layer["description"] = mapping_yaml["description"]

                for technique in mapping_yaml.get("techniques", []):
                    tech = {"id": technique["id"], "scores": technique["technique-scores"]}
                    tech = self.get_tech_or_sub(tech, mapping_yaml, unit_mode)
                    self.add_technique_or_sub(techniques, tech)

                    for sub_tech_scores in technique.get("sub-techniques-scores", []):
                        for sub_tech in sub_tech_scores.get("sub-techniques", []):
                            sub = {"id": sub_tech["id"], "scores": sub_tech_scores["scores"]}
                            sub = self.get_tech_or_sub(sub, mapping_yaml, unit_mode)
                            self.add_technique_or_sub(techniques, sub)

            layer["techniques"].extend(list(techniques.values()))
            layer["legendItems"] = self.get_legend()
            if unit_mode:
                names = ",".join(names)
                if(not layer["description"]):
                    layer["description"] = f"Controls: {names}"
            self.output(options, mapping_file, json.dumps(layer, indent=4))