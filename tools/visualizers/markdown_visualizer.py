from visualizers.base_visualizer import AbstractVisualizer
import markdown
from mdutils.mdutils import MdUtils
import yaml
import os

class MarkdownVisualizer(AbstractVisualizer):

    @staticmethod
    def get_name():
        return "Markdown"


    def get_output_extension(self):
        return "md"


    def get_output_folder_name(self):
        return "markdowns"


    def write_visualization(self, output_name, visualization):
        visualization.file_name = output_name
        visualization.create_md_file()

        pre, _ = os.path.splitext(output_name)
        html_name = ".".join([pre, "html"])

        markdown.markdownFromFile(extensions= ['tables', 'nl2br', 'sane_lists'], 
            input=visualization.file_name, output=html_name, encoding='utf8')
        
    
    def write_header(self, mdFile, mapping_yaml, fields):
        for field in fields:
            value = mapping_yaml.get(field, None)
            if not value == None:
                mdFile.write(field.capitalize() + ':', bold_italics_code='b')
                mdFile.write(' ' + str(mapping_yaml[field]))
                mdFile.write('  \n\n')

    
    def write_scores(self, mdFile, scores):
        md_scores = ["Category", "Value", "Comment"]
        for score in scores:
            md_scores.extend([score["category"], score["value"], score.get("comment", "")])
        mdFile.new_table(columns=3, rows=len(scores) + 1, text=md_scores, text_align='center')
        mdFile.write('  \n\n')


    def write_techniques(self, mdFile, techniques):
        mdFile.new_header(level=2, title="Techniques", add_table_of_contents='n')

        for technique in techniques:
            mdFile.new_header(level=3, title=f"{technique['id']} - {technique['name']}", add_table_of_contents='n')
            mdFile.write('  \n\n')

            scores = technique["technique-scores"]
            self.write_scores(mdFile, scores)

            subs = technique.get('sub-techniques-scores', [])
            if subs:
                mdFile.new_header(level=4, title=f"Sub-technique Scores", add_table_of_contents='n')
                group_index = 0
                for st_score in subs:
                    group_index += 1
                    mdFile.new_line(f'- Group {group_index}:')
                    mdFile.new_line('\t- Sub-Techniques:')
                    for st in st_score["sub-techniques"]:
                        mdFile.new_line(f"\t\t- {st['id']} - {st['name']}")

                    mdFile.new_line()
                    scores = st_score["scores"]
                    self.write_scores(mdFile, scores)


    def visualize(self, mapping_files, options = {}):
        for mapping_file in mapping_files:
            with open(mapping_file, "r") as f:
                mapping_yaml = yaml.safe_load(f)
            
            mdFile = MdUtils(file_name="", title=mapping_yaml['name'])

            header_fields = ["version", "ATT&CK version", "creation date", "last update", "name", 
                "description", "author", "contact", "organization", "platform"]
            self.write_header(mdFile, mapping_yaml, header_fields)

            for key in mapping_yaml:
                if key == "techniques":
                    self.write_techniques(mdFile, mapping_yaml[key])
                elif key == "comments":
                    mdFile.new_header(level=2, title=key.capitalize(), add_table_of_contents='n')
                    mdFile.new_paragraph(mapping_yaml["comments"])
                    mdFile.write('  \n\n')
                elif key == "tags":
                    mdFile.new_header(level=2, title=key.capitalize(), add_table_of_contents='n')
                    for tag in mapping_yaml.get(key, []):
                        mdFile.write(f"- {tag}\n")
                    mdFile.write('  \n\n')
                elif key == "references":
                    mdFile.new_header(level=2, title=key.capitalize(), add_table_of_contents='n')
                    for reference in mapping_yaml[key]:
                        mdFile.write(f"- {reference}\n")
                    mdFile.write('  \n\n')
                elif not key in header_fields:
                    print(f"  Field {key} not visualized.")

            self.output(options, mapping_file, mdFile)