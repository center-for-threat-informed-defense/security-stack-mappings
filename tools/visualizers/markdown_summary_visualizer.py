from visualizers.base_visualizer import AbstractVisualizer
import markdown
from mdutils.mdutils import MdUtils
from mdutils.tools.Header import Header
from pathlib import Path
import yaml
import os
import json

class MarkdownSummaryVisualizer(AbstractVisualizer):

    def __init__(self):
        super().__init__()

        with open("config/markdown_summary.json", "r") as f:
            self.platform_summaries = json.load(f)


    @staticmethod
    def get_name():
        return "MarkdownSummary"


    def get_output_extension(self):
        return ""


    def get_output_folder_name(self):
        return ""


    def write_visualization(self, output_name, visualization):
        visualization.file_name = output_name
        visualization.new_table_of_contents(table_title='Contents', depth=2)
        visualization.create_md_file()

        pre, _ = os.path.splitext(output_name)
        html_name = ".".join([pre, "html"])

        #markdown.markdownFromFile(extensions= ['tables', 'nl2br', 'sane_lists'], 
            #input=visualization.file_name, output=html_name, encoding='utf8')


    def visualize_platform_controls(self, platform, platform_data, mdFile):
        mdFile.new_header(level=1, title="Controls", add_table_of_contents='y')
        for control_name in sorted(list(platform_data.keys())):
            control_data = platform_data[control_name]
            mdFile.new_header(level=2, title=control_name, add_table_of_contents='y')
            mdFile.new_paragraph(control_data[0])

            mapping = control_data[1]
            layer = control_data[2]
            pre, _ = os.path.splitext(layer)
            layer = pre + ".json"
            mdFile.write("\n\n")
            mdFile.write(f"- [Mapping File]({mapping})\n")
            mdFile.write(f"- [Navigator Layer]({layer})\n")
            #mdFile.write(f"- [Navigator Layer](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL={layer})\n")

            techniques = control_data[6]
            techniques.sort()
            mdFile.new_header(level=3, title="Technique(s)", add_table_of_contents='n')
            for technique in techniques:
                mdFile.write(f"- {technique}\n")
            mdFile.write('  \n\n')

            comments = control_data[3]
            if comments:
                mdFile.new_header(level=3, title="Mapping Comments", add_table_of_contents='n')
                mdFile.new_paragraph(comments)
                mdFile.write('  \n\n')

            tags = control_data[5]
            if tags:
                tags.sort()
                mdFile.new_header(level=3, title="Tag(s)", add_table_of_contents='n')
                for tag in tags:
                    mdFile.write(f"- {Header.header_anchor(tag)}\n")
                mdFile.write('  \n\n')

            references = control_data[4]
            mdFile.new_header(level=3, title="Reference(s)", add_table_of_contents='n')
            for reference in references:
                mdFile.write(f"- {reference}\n")
            mdFile.write('  \n\n')
        
    
    def visualize_platform_tags(self, platform, platform_tags, mdFile):
        mdFile.new_header(level=1, title="Tags", add_table_of_contents='y')

        for tag in sorted(list(platform_tags.keys())):
            controls = platform_tags[tag]
            controls.sort()
            mdFile.new_header(level=2, title=tag, add_table_of_contents='y')
            mdFile.new_header(level=3, title="Controls", add_table_of_contents='n')
            for control in controls:
                mdFile.write(f"- {Header.header_anchor(control)}\n")

            #mdFile.write('\n\n')
            mdFile.new_header(level=3, title="Navigator Layer", add_table_of_contents='n')
            layer = "changeme"
            mdFile.write(f"- [View]({layer})\n")


    def load_platform_tags(self, platform, platform_path):
        tags = {}
        tags_path = platform_path.joinpath("valid_tags.txt")
        if tags_path.exists():
            with open(tags_path) as tags_file:
                tags =  drugs = [line.rstrip('\n') for line in tags_file]
                tags = dict((tag, []) for tag in tags)
        else:
            print(f"Warning:  Platform {platform} doesn't have a tags file located here:  {tags_path}")

        return tags


    def visualize(self, mapping_files, options = {}):
        summary_data = {}
        for mapping_file in mapping_files:
            mapping_path = Path(mapping_file)
            with open(mapping_file, "r") as f:
                mapping_yaml = yaml.safe_load(f)
            
            platform = mapping_yaml["platform"]
            _, platform_data, platform_tags = summary_data.get(platform, ["", {}, {}])
            if not platform_data:
                platform_tags = self.load_platform_tags(platform, mapping_path.parent)
                summary_data[platform] = [str(mapping_path.parent.joinpath("README.md")), platform_data, platform_tags]

            platform_data[mapping_yaml['name']] = []
            platform_data[mapping_yaml['name']].append(mapping_yaml.get("description", ""))
            platform_data[mapping_yaml['name']].append(mapping_path.name)
            platform_data[mapping_yaml['name']].append("/".join(["layers", mapping_path.name]))
            platform_data[mapping_yaml['name']].append(mapping_yaml.get("comments", ""))
            platform_data[mapping_yaml['name']].append(mapping_yaml.get("references", []))

            tags = mapping_yaml.get("tags", [])
            platform_data[mapping_yaml['name']].append(tags)
            for tag in tags:
                platform_tags[tag].append(mapping_yaml['name'])

            techniques = []
            for technique in mapping_yaml.get("techniques", []):
                technique = f"[{technique['id']} - {technique['name']}](https://attack.mitre.org/techniques/{technique['id']}/)"
                techniques.append(technique)
            platform_data[mapping_yaml['name']].append(techniques)

        for platform, platform_data in summary_data.items():
            mdFile = MdUtils(file_name="", title=f"{platform} Controls")

            summary = self.platform_summaries.get(platform, "")
            mdFile.new_header(level=1, title="Introduction", add_table_of_contents='y')
            mdFile.new_paragraph(summary)

            self.visualize_platform_controls(platform, platform_data[1], mdFile)
            self.visualize_platform_tags(platform, platform_data[2], mdFile)

            readme_path = platform_data[0]
            options["output_absolute_filename"] = readme_path

            self.output(options, mapping_file, mdFile)