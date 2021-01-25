from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Collection

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
        techniques = self.tc_src.query([Filter("type", "=", "attack-pattern")])
        return techniques