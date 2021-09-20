from visualizers.base_visualizer import AbstractVisualizer
import markdown
from mdutils.mdutils import MdUtils
from mdutils.tools.Header import Header
from pathlib import Path
from io import BytesIO
import yaml
import os
import json

from utils.utils import get_project_root

class MarkdownSummaryVisualizer(AbstractVisualizer):

    def __init__(self):
        super().__init__()

        self.html_template = False
        root_dir = get_project_root()
        with open(f"{root_dir}/tools/config/markdown_summary_config.json", "r") as f:
            self.config = json.load(f)


    @staticmethod
    def get_name():
        return "MarkdownSummary"


    def initialize_html_template(self, platform):
        root_dir = get_project_root()
        platform = platform.lower()
        with open(f"{root_dir}/tools/config/{platform}_markdown_summary_template.html", "r") as f:
            self.html_template = f.read()


    def get_output_extension(self):
        return ""


    def get_output_folder_name(self):
        return ""


    def write_visualization(self, output_name, visualization):
        visualization.file_name = output_name
        visualization.new_table_of_contents(table_title='Contents', depth=2, marker="<TOC_MARKER>")
        visualization.create_md_file()

        if self.html_template:
            pre, _ = os.path.splitext(output_name)
            html_name = ".".join([pre, "html"])

            markdown_data = BytesIO()
            markdown.markdownFromFile(extensions= ['tables', 'nl2br', 'sane_lists'], 
                input=visualization.file_name, output=markdown_data, encoding='utf8')
            
            print(f"   Generating {html_name}")
            with open(html_name, "w") as f:
                f.write(self.html_template.replace("<CONTENT_HERE>", markdown_data.getvalue().decode('UTF-8')))


    def get_control_reference(self, control):
        item = Header.header_anchor(control)
        # Don't include the control # in the link display
        item = item.split(" ")
        item = "[" + " ".join(item[1:]).replace(".", "")
        return item


    def get_list_item(self, index, name):
        return f"{index}. {name}"
        
    
    def visualize_platform_controls(self, platform, platform_data, platform_tags, mdFile):
        mdFile.new_header(level=1, title="Controls", add_table_of_contents='y')
        control_index = 0
        controls_map = {}
        for control_name in sorted(list(platform_data.keys())):
            control_index += 1
            control_data = platform_data[control_name]
            title = self.get_list_item(control_index, control_name)
            controls_map[control_name] = title
            mdFile.new_header(level=2, title=title, add_table_of_contents='y')
            mdFile.new_paragraph(control_data[0])

            mapping = control_data[1]
            layer = control_data[2]
            pre, _ = os.path.splitext(layer)
            layer = pre + ".json"
            mdFile.write("\n\n")
            mdFile.write(f"- [Mapping File]({mapping}) ([YAML]({mapping}))\n")
            mdFile.write(f"- [Navigator Layer]({layer}) ([JSON]({layer}))\n")

            comments = control_data[3]
            if comments:
                mdFile.new_header(level=3, title="Mapping Comments", add_table_of_contents='n')
                mdFile.new_paragraph(comments)
                mdFile.write('  \n\n')

            techniques = control_data[6]
            techniques.sort()
            mdFile.new_header(level=3, title="Technique(s)", add_table_of_contents='n')
            table_data = ["Technique", "Category", "Value", "Comment"]
            for tech in techniques:
                table_data.extend(tech)
            mdFile.new_table(4, len(techniques) + 1, text=table_data, text_align='left')
            mdFile.write('  \n\n')

            tags = control_data[5]
            if tags:
                tags.sort()
                mdFile.new_header(level=3, title="Tag(s)", add_table_of_contents='n')
                for tag in tags:
                    tag_index = platform_tags.index(tag) + 1
                    ref = self.get_control_reference(self.get_list_item(tag_index, tag))
                    mdFile.write(f"- {ref}\n")
                mdFile.write('  \n\n')

            references = control_data[4]
            mdFile.new_header(level=3, title="Reference(s)", add_table_of_contents='n')
            for reference in references:
                reference = reference.replace('"', "")
                mdFile.write(f"- <{reference}>\n")
            mdFile.write('  \n\n')
            mdFile.write('  [Back to Table Of Contents](#contents)')
        
        return controls_map

    
    def visualize_platform_tags(self, platform, platform_tags, controls_map, mdFile):
        mdFile.new_header(level=1, title="Control Tags", add_table_of_contents='y')

        tag_index = 0
        for tag in sorted(list(platform_tags.keys())):
            tag_index += 1
            controls = platform_tags[tag]
            controls.sort()
            tag_title = self.get_list_item(tag_index, tag)
            mdFile.new_header(level=2, title=tag_title, add_table_of_contents='y')
            mdFile.new_header(level=3, title="Controls", add_table_of_contents='n')
            for control in controls:
                ref = self.get_control_reference(controls_map[control])
                mdFile.write(f"- {ref}\n")

            #mdFile.write('\n\n')
            mdFile.new_header(level=3, title="Views", add_table_of_contents='n')
            layer_name = tag.replace(" ", "_")
            layer = f"layers/tags/{layer_name}.json"
            mdFile.write(f"- [Navigator Layer]({layer}) ([JSON]({layer}))\n")

            mdFile.write('  \n\n')
            mdFile.write('  [Back to Table Of Contents](#contents)')


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


    def get_technique_rows(self, technique):
        techs = []
        desc = f"[{technique['id']} - {technique['name']}](https://attack.mitre.org/techniques/{technique['id']}/)"
        for score in technique["technique-scores"]:
            comment = score.get("comments", "").replace("\n", "<br/>").strip()
            techs.append([desc, score['category'], score['value'], comment])

        return techs


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
            # account for the tag element being present in the yaml but empty
            if not tags:
                tags = []
            platform_data[mapping_yaml['name']].append(tags)
            for tag in tags:
                platform_tags[tag].append(mapping_yaml['name'])

            techniques = []
            for technique in mapping_yaml.get("techniques", []):
                technique_rows = self.get_technique_rows(technique)
                techniques.extend(technique_rows)
            platform_data[mapping_yaml['name']].append(techniques)

        for platform, platform_data in summary_data.items():
            title = self.config["titles"].get(platform, f"{platform} Controls")
            summary = self.config["summaries"].get(platform, "")

            mdFile = MdUtils(file_name="", title=title)

            if not summary:
                print(f"  Warning:  Platform {platform} does not provide summary text from tools/config/markdown_summary.json")
            mdFile.new_paragraph(summary)
            mdFile.new_paragraph("[Aggregate Navigator Layer For All Controls](layers/platform.json) ([JSON](layers/platform.json))")

            mdFile.new_paragraph("<TOC_MARKER>")

            tags = list(platform_data[2])
            tags.sort()
            control_map = self.visualize_platform_controls(platform, platform_data[1], tags, mdFile)
            self.visualize_platform_tags(platform, platform_data[2], control_map, mdFile)

            if options.get("output_dir", None):
                platform_dir = os.path.join(options["output_dir"], platform)
                if not os.path.exists(platform_dir):
                    os.makedirs(platform_dir)
                options["output_absolute_filename"] = os.path.join(platform_dir, "README.md")
            else:
                readme_path = platform_data[0]
                options["output_absolute_filename"] = readme_path

            if options.get("include-html", False):
                self.initialize_html_template(platform)

            self.output(options, mapping_file, mdFile)
