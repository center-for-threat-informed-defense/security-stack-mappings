from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.model import Base, Tactic, Technique, SubTechnique

class MappingDatabase:

    def __init__(self, attack_ds):
        self.attack_ds = attack_ds

    def init_database(self):
        engine = create_engine(f"sqlite:///mapping.db")
        Base.metadata.create_all(engine)
        
        Session = sessionmaker()
        Session.configure(bind=engine)
        self.session = Session()
        row_count = self.session.query(Tactic).count()
        if not row_count:
            self.build_attack_database()


    def build_attack_database(self):
        tactics = self.attack_ds.get_tactics()
        for tactic_name, tactic_id in tactics.items():
            tactic_entity = Tactic()
            tactic_entity.name = tactic_name
            tactic_entity.attack_id = tactic_id

            self.session.add(tactic_entity)
            print(tactic_name)
            techniques = self.attack_ds.get_tactic_techniques(tactic_name)
            for technique in techniques:
                technique_name = technique["name"]
                attack_id = self.attack_ds.get_attack_id(technique)
                technique_entity = self.session.query(Technique).filter_by(attack_id=attack_id).first()
                if not technique_entity:
                    technique_entity = Technique()
                    technique_entity.name = technique_name
                    technique_entity.attack_id = self.attack_ds.get_attack_id(technique)
                    technique_entity.tactics.append(tactic_entity)
                    self.session.add(technique_entity)
                else:
                    technique_entity.tactics.append(tactic_entity)

            self.session.commit()

        sub_ts = self.attack_ds.get_subtechniques()
        for sub_tech in sub_ts:
            attack_id = self.attack_ds.get_attack_id(sub_tech)
            technique_id = attack_id.split('.')[0]
            technique = self.session.query(Technique).filter_by(attack_id=technique_id).one()

            sub_tech_entity = SubTechnique()
            sub_tech_entity.name = sub_tech["name"]
            sub_tech_entity.attack_id = attack_id
            sub_tech_entity.technique = technique
            self.session.add(sub_tech_entity)
            print(f"{technique_id} {sub_tech['name']} {attack_id}")

        self.session.commit()