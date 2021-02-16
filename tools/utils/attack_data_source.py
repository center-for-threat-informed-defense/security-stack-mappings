from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Collection

import json

class AttackDataSource:

    ENTERPRISE_ATTACK_COLLECTION = "95ecc380-afe9-11e4-9b6c-751b66dd541e"

    def __init__(self):
        self.collection = Collection(
            f"https://cti-taxii.mitre.org/stix/collections/"
            f"{AttackDataSource.ENTERPRISE_ATTACK_COLLECTION}")
        # Supply the collection to TAXIICollection
        self.tc_src = TAXIICollectionSource(self.collection)


    def get_tactics(self):
        tactics = {}
        matrix = self.tc_src.query([ Filter('type', '=', 'x-mitre-matrix'),])
        for tactic_id in matrix[0]['tactic_refs']:
            tactic = self.tc_src.get(tactic_id)
            name = tactic["name"]
            tactics[name] = self.get_attack_id(tactic)
    
        return tactics


    def get_attack_id(self, attack_entity):
        for external_ref in attack_entity["external_references"]:
            if external_ref["source_name"] == "mitre-attack":
                return external_ref["external_id"]


    def get_tactic_techniques(self, tactic_name):
        tactic_name = tactic_name.lower().replace(" ", "-")
        techniques = self.tc_src.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('kill_chain_phases.phase_name', '=', tactic_name),
            Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
            Filter('x_mitre_is_subtechnique', '=', False)
        ])
        return techniques
    

    def get_subtechniques(self):
        sub_ts = self.tc_src.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', True)
        ])
        return sub_ts


    def get_techniques(self):
        techniques = self.tc_src.query([
            Filter("type", "=", "attack-pattern"),
            Filter('x_mitre_is_subtechnique', '=', False)
        ])
        return techniques

    
    def get_techniques_and_sub_techniques(self, sub_technique_keys = True):
        techniques = self.get_techniques()
        output_techniques = {}

        for technique in techniques:
            tech = {}
            tech_id = self.get_attack_id(technique)
            tech["technique_id"] = tech_id
            tech["technique_name"] = technique["name"]
            tech["platforms"] = technique.get("x_mitre_platforms", [])
            if sub_technique_keys:
                tech["sub_techniques"] = {}
            else:
                tech["sub_techniques"] = []

            output_techniques[tech_id] = tech

        sub_techs = self.get_subtechniques()
        for sub_ts in sub_techs:
            attack_id = self.get_attack_id(sub_ts)
            technique_id = attack_id.split('.')[0]

            sub_tech = {}
            sub_tech["sub_technique_id"] = attack_id
            sub_tech["sub_technique_name"] = sub_ts["name"]
            sub_tech["platforms"] = sub_ts.get("x_mitre_platforms", [])

            if sub_technique_keys:
                output_techniques[technique_id]["sub_techniques"][attack_id] = sub_tech
            else:
                output_techniques[technique_id]["sub_techniques"].append(sub_tech)
        
        return output_techniques


    def output_attack_json(self, false):
        output_techniques = self.get_techniques_and_sub_techniques()
        with open("techniques.json", "w") as f:
            json.dump(output_techniques, f, indent=4)