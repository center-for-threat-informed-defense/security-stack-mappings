import os
import yaml
import json

def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise NotADirectoryError(path)

def verify_tags(mapping_file):
    fn = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config/valid_tags.yaml')
    with open(fn) as file_object:
        with open(mapping_file) as f:
            mf = yaml.safe_load(f)
            valid_tags = yaml.safe_load(file_object)
            for tag in mf['tags']:
                if tag in valid_tags:
                    continue
                else:
                    print('Tag ' + tag + ' from mapping file ' + mf['name'] + ' is not contained within valid_tags.yaml.')
                    return

def verify_attack_info(mapping_file):
    try:
        techniques_filepath = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'techniques.json')
    except:
        print('Generate the techniques.json file by using the output-techniques-json action')

    with open(techniques_filepath) as file_object:
        with open(mapping_file) as f:
            techniques_json = json.load(file_object)
            mapping = yaml.safe_load(f)
            for technique in mapping['techniques']:
                tech_id = technique['id']
                tech_name = technique['name']
                sub_list = []
                if tech_id in techniques_json:
                    for x in techniques_json[tech_id]['sub_techniques']:
                        sub_list.append(x['sub_technique_id'])
                        sub_list.append(x['sub_technique_name'])

                    if tech_name == techniques_json[tech_id]['technique_name']:
                        for sub_techs in technique['sub-techniques-scores']:
                            for subs in sub_techs['sub-techniques']:
                                if subs['id'] in sub_list and subs['name'] in sub_list:
                                    continue
                                else:
                                    print(subs['id'] + ' ' + subs['name'] + ' is not a correct sub-technique of ' + tech_name)
                    else:
                        print('Error: Technique name ' + tech_name + ' from mapping file does not match technique name ' + techniques_json[tech_id]['technique_name'])
                else:
                    print('Error ' + tech_id + ' is not a valid ATT&CK Technique ID.')

def verify_scores(mapping_file):
    with open(mapping_file) as f:
        mapping = yaml.safe_load(f)
        for technique in mapping['techniques']:
            if not technique['technique-scores'] and not technique['sub-techniques-scores'][0]['scores']:
                print('Error: There are no scores for ' + technique['name'])
                return

            if technique['technique-scores']:
                tech_scores = technique['technique-scores']
                cat_list = []
                for score in tech_scores:
                    cat_list.append(score['category'])
                    if cat_list.count(score['category']) > 1:
                        print("Error: There is more than one score of type " + score['category'] + ' in technique-scores for ' + technique['name'])

            for subs in technique['sub-techniques-scores']:
                if subs['scores']:
                    sub_scores = subs['scores']
                    cat_list = []
                    for score in sub_scores:
                        cat_list.append(score['category'])
                        if cat_list.count(score['category']) > 1:
                            print("Error: There is more than one score of type " + score['category'] + ' in sub-techniques-scores for ' + technique['name'])