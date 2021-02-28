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


    def visualize(self, mapping_files, options = {}):
        for mapping_file in mapping_files:
            with open(mapping_file, "r") as f:
                mapping_yaml = yaml.safe_load(f)
            
            mdFile = MdUtils(file_name="", title=mapping_yaml['name'])

            for key in mapping_yaml:
                if(key == "techniques"):
                    mdFile.new_header(level=1, title=key.capitalize())
                    techs = mapping_yaml[key]

                    for k in techs:
                        mdFile.write('Id:', bold_italics_code='b')
                        mdFile.write(' ' + str(k['id']))
                        mdFile.write('  \n\n')
                        mdFile.write('Name:', bold_italics_code='b')
                        mdFile.write(' ' + str(k['name']))
                        mdFile.write('  \n\n')
                        mdFile.write('Sub-Techniques:', bold_italics_code='b')
                        mdFile.write('  \n\n')
                        subs = k.get('sub-techniques', [])

                        if subs:
                            sub_counter = 1
                            sub_list = ["Id", "Name", "Category", "Value", "Comment"]

                            for i in subs:
                                scores = i['scores']
                                for j in scores:
                                    sub_counter += 1
                                    sub_list.append(str(i['id']))
                                    sub_list.append(str(i['name']))
                                    sub_list.append(str(j['category']))
                                    sub_list.append(str(j['value']))
                                    sub_list.append(str(j['comment']))

                            mdFile.new_table(columns=5, rows=sub_counter, text=sub_list, text_align='left')
                            mdFile.write('\n***\n')

                else:
                    mdFile.write(key.capitalize() + ':', bold_italics_code='b')
                    mdFile.write(' ' + str(mapping_yaml[key]))
                    mdFile.write('  \n\n')

                self.output(options, mapping_file, mdFile)