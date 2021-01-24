from visualizers.base_visualizer import AbstractVisualizer
from mdutils.mdutils import MdUtils
import yaml
import os

class MarkdownVisualizer(AbstractVisualizer):

    @staticmethod
    def get_name():
        return "Markdown"

    def visualize(self, mapping_files, options = {}):
        output_dir = options["output_dir"]
        for mapping_file in mapping_files:
            fname = os.path.join(output_dir, mapping_file.name)
            mdFile = MdUtils(file_name=fname, title='Cloud Security Mapping')
            #mdFile.new_header(level=1, title='Overview')
            with open(mapping_file, "r") as f:
                mapping_yaml = yaml.safe_load(f)

            for key in mapping_yaml:
                if(key == "techniques"):
                    mdFile.new_header(level=1, title=key)
                    techs = mapping_yaml[key]
                    tech_list = []
                    for k in techs:
                        tech_list.append('id: ' + str(k['id']))
                        tech_list.append('name: ' + str(k['name']))
                        tech_list.append('sub-techniques: ')
                        subs = k['sub-techniques']
                        for i in subs:
                            sub_list = []
                            sub_list.append('id: ' + str(i['id']))
                            sub_list.append('name: ' + str(i['name']))
                            sub_list.append('scores: ')
                            scores = i['scores']
                            for j in scores:
                                scores_list = []
                                scores_list.append('function: ' + str(j['function']))
                                scores_list.append('value: ' + str(j['value']))
                                scores_list.append('comment: ' + str(j['comment']))
                                sub_list.append(scores_list)
                            tech_list.append(sub_list)
                    mdFile.new_list(items = tech_list)
                else:
                    mdFile.new_header(level=1, title=key)
                    mdFile.new_paragraph('\t'+str(mapping_yaml[key]))

            mdFile.create_md_file()