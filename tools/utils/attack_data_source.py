from stix2 import MemoryStore, TAXIICollectionSource, Filter
from taxii2client.v20 import Collection

import re
import json
import requests

class AttackDataSource:

    ENTERPRISE_ATTACK_COLLECTION = "enterprise-attack"

    def __init__(self):
        self.versions = self.get_versions()
        self.latest_attack_version = self.versions[-1]
        self.current_version = None
        self.tc_src = None


    def get_versions(self):
        refToTag = re.compile(r"ATT&CK-v(.*)")
        tags = requests.get("https://api.github.com/repos/mitre/cti/git/refs/tags").json()
        versions = list(map(lambda tag: refToTag.search(tag["ref"]).groups()[0],
            filter(lambda tag: "ATT&CK-v" in tag["ref"], tags)))

        return versions


    def set_attack_version(self, version=None):
        version = version if version else self.latest_attack_version

        if self.tc_src and self.current_version == version:
            return

        domain = self.ENTERPRISE_ATTACK_COLLECTION
        stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}/{domain}/{domain}.json").json()
        self.tc_src = MemoryStore(stix_data=stix_json["objects"])
        self.current_version = version


    def get_tactics(self, version = None):
        self.set_attack_version(version)

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


    def get_tactic_techniques(self, tactic_name, version = None):
        self.set_attack_version(version)

        tactic_name = tactic_name.lower().replace(" ", "-")
        techniques = self.tc_src.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('kill_chain_phases.phase_name', '=', tactic_name),
            Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
            Filter('x_mitre_is_subtechnique', '=', False)
        ])
        return techniques
    

    def get_subtechniques(self, version = None):
        self.set_attack_version(version)

        sub_ts = self.tc_src.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', True)
        ])
        return sub_ts


    def get_techniques(self, version = None):
        self.set_attack_version(version)

        techniques = self.tc_src.query([
            Filter("type", "=", "attack-pattern"),
            Filter('x_mitre_is_subtechnique', '=', False)
        ])
        return techniques

    
    def get_techniques_and_sub_techniques(self, sub_technique_keys = True, version = None):
        self.set_attack_version(version)

        techniques = self.get_techniques(version)
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

        sub_techs = self.get_subtechniques(version)
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


    def output_attack_json(self, version = None):
        self.set_attack_version(version)

        output_techniques = self.get_techniques_and_sub_techniques(False, version)
        print("  Outputting techniques.json ...")
        with open("techniques.json", "w") as f:
            json.dump(output_techniques, f, indent=4)
