from visualizers.base_visualizer import AbstractVisualizer
import yaml
import json
import os
import copy

from utils.utils import get_project_root

class AttackNavigatorVisualizer(AbstractVisualizer):


    def __init__(self):
        super().__init__()

        root_dir = get_project_root()
        with open(f"{root_dir}/tools/config/navigator_layer_template.json", "r") as f:
            self.layer_template = json.load(f)

        with open(f"{root_dir}/tools/config/navigator_layer_config.yaml", "r") as f:
            self.config = yaml.safe_load(f)

        self.legend = []
        self.tag_mode = False
        self.tags = {}
        self.controls_by_platform = {}


    @staticmethod
    def get_name():
        return "AttackNavigator"


    def get_output_extension(self):
        return "json"


    def get_output_folder_name(self):
        if self.tag_mode:
            return "layers/tags"
        else:
            return "layers"


    def print_statistics(self, platform, layer, mappings):
        technique_count = 0
        subtechnique_count = 0

        for entity in layer["techniques"]:
            if "." in entity["techniqueID"]:
                subtechnique_count += 1
            else:
                technique_count += 1

        num_mappings = len(mappings)
        print(f"\n{platform} Platform:  Mappings:  {num_mappings} Techniques:  {technique_count} Sub-techniques:  {subtechnique_count}")


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
            metadata.append({"name": "comment", "value": score.get("comments","n/a")})
            metadata.append({"divider": True})
            scores.append(score["value"])
            category = score["category"]

        metadata = metadata[:-1]
        scores.sort()
        max_score = scores[-1]
        category = category if len(scores) == 1 else "Mixed"

        return metadata, category, max_score


    def get_tech_or_sub(self, entity, mapping_yaml):
        tech = {}
        tech["techniqueID"] = entity["id"]
        tech["enabled"] = True
        tech["showSubtechniques"] = False

        metadata, category, max_score = self.get_scores_data(entity["scores"])
        tech["metadata"] = metadata
        if self.tag_mode:
            tech["metadata"].insert(0, {"name": "control", "value": mapping_yaml["name"]})

        color = self.config["score_colors"][category][max_score]
        tech["color"] = color

        tech["score_num"] = self.config["score_values"][max_score]
        if self.config["include_numeric_scores"]:
            tech["score"] = self.config["score_values"][max_score]

        tech["score_display"] = max_score
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

            copy_src = existing if existing["score_num"] > entity["score_num"] else entity
            score_display = copy_src["score_display"]
            color = self.config["score_colors"][existing["category"]][score_display]
            existing["color"] = color
            if self.config["include_numeric_scores"]:
                existing["score"] = copy_src["score"]
            existing["score_display"] = score_display
            existing["score_num"] = copy_src["score_num"]
        else:
            techniques[entity_id] = entity

    def visualize_mapping_file(self, mapping_file, layer, techniques):
        print(f"  Processing mapping file {mapping_file} ...")
        with open(mapping_file, "r") as f:
            mapping_yaml = yaml.safe_load(f)
            layer["name"] = mapping_yaml["name"]
            layer["description"] = mapping_yaml["description"]
            attack_version = self.config["platform_attack_versions"][mapping_yaml["platform"]]
            layer["versions"]["attack"] = str(attack_version)

            for technique in mapping_yaml.get("techniques", []):
                tech = {"id": technique["id"], "scores": technique["technique-scores"]}
                tech = self.get_tech_or_sub(tech, mapping_yaml)
                self.add_technique_or_sub(techniques, tech)

                for sub_tech_scores in technique.get("sub-techniques-scores", []):
                    for sub_tech in sub_tech_scores.get("sub-techniques", []):
                        sub = {"id": sub_tech["id"], "scores": sub_tech_scores["scores"]}
                        sub = self.get_tech_or_sub(sub, mapping_yaml)
                        self.add_technique_or_sub(techniques, sub)

            return mapping_yaml["name"], mapping_yaml["platform"], mapping_yaml.get("tags", [])


    
    def visualize_mapping(self, mapping_file, options):
        layer = copy.deepcopy(self.layer_template)
        techniques = {}

        self.tag_mode = type(mapping_file) is list

        if self.tag_mode:
            # mapping_file is actually a list of files, e.g. mapping files that share a tag
            m_files = mapping_file

            names = []
            for mapping_file in m_files:
                name, _, _ = self.visualize_mapping_file(mapping_file, layer, techniques)
                names.append(name)

            options["output_filename"] = options["title"].replace(" ", "_")
            layer["name"] = options["title"]
            layer["description"] = options.get("description", None)
            if not layer["description"]:
                names = ",".join(names)
                layer["description"] = f"Controls: {names}"
        else:
            name, platform, mapping_tags = self.visualize_mapping_file(mapping_file, layer, techniques)
            platform_tags = self.tags.get(platform, {})
            if not platform_tags:
                self.tags[platform] = platform_tags

            if mapping_tags:
                for tag in mapping_tags:
                    platform_tag = platform_tags.get(tag, [])
                    if not platform_tag:
                        platform_tags[tag] = platform_tag
                    platform_tag.append(mapping_file)

            platform_controls = self.controls_by_platform.get(platform, [])
            if not platform_controls:
                self.controls_by_platform[platform] = platform_controls
            platform_controls.append(mapping_file)

        layer["techniques"].extend(list(techniques.values()))
        layer["legendItems"] = self.get_legend()
        return layer


    def visualize(self, mapping_files, options):
        for mapping_file in mapping_files:
            layer = self.visualize_mapping(mapping_file, options)
            if self.tag_mode:
                mapping_file = mapping_file[0]
            self.output(options, mapping_file, json.dumps(layer, indent=4))

        if options["include-aggregates"]:
            for platform, platform_tags in self.tags.items():
                for tag in platform_tags:
                    options["title"] = tag
                    mappings = platform_tags[tag]
                    if mappings:
                        layer = self.visualize_mapping(mappings, options)
                        self.output(options, mappings[0], json.dumps(layer, indent=4))

            for platform, mappings in self.controls_by_platform.items():
                options["title"] = f"{platform} platform native security controls"
                layer = self.visualize_mapping(mappings, options)
                options["output_filename"] = "platform"
                self.tag_mode = False
                self.output(options, mappings[0], json.dumps(layer, indent=4))
                self.print_statistics(platform, layer, mappings)
