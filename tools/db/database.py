from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from db.model import Base, Tactic, Technique, SubTechnique, Mapping, Tag

import yaml

class MappingDatabase:

    def __init__(self, attack_ds):
        self.attack_ds = attack_ds
        self.engine = create_engine(f"sqlite:///mapping.db")
        Base.metadata.create_all(self.engine)
        
        Session = sessionmaker()
        Session.configure(bind=self.engine)
        self.session = Session()


    def init_database(self, mapping_files, tags):
        Base.metadata.drop_all(self.engine)
        Base.metadata.create_all(self.engine)
        self.build_attack_database()
        self.build_mapping_database(mapping_files, tags)


    def query_mapping_files(self, tags, relationship):
        if tags:
            mapping_entities = self.session.query(Mapping).select_from(Mapping)\
                .join(Mapping.tags).filter(Tag.name.in_(tags)).group_by(Mapping.mapping_id)
            if relationship == "AND":
                mapping_entities = mapping_entities.having(func.count(Tag.tag_id) == len(tags))
        else:
            mapping_entities = self.session.query(Mapping)

        return mapping_entities


    def build_mapping_database(self, mapping_files, tags):
        for tag in tags:
            tag_entity = Tag()
            tag_entity.name = tag
            self.session.add(tag_entity)
            self.session.flush()

        for mapping_file in mapping_files:
            with open(mapping_file, "r") as f:
                mapping_yaml = yaml.safe_load(f)

            mapping_entity = Mapping()
            mapping_entity.name = mapping_yaml["name"]
            mapping_entity.path = str(mapping_file)
            mapping_entity.platform = mapping_yaml["platform"]
            mapping_entity.description = mapping_yaml["description"]
            self.session.add(mapping_entity)

            yaml_tags = mapping_yaml.get("tags", [])
            if yaml_tags:
                tag_entities = self.session.query(Tag).filter(Tag.name.in_(yaml_tags)).all()
                mapping_entity.tags.extend(tag_entities)


        self.session.commit()


    def build_attack_database(self):
        tactics = self.attack_ds.get_tactics()
        for tactic_name, tactic_id in tactics.items():
            tactic_entity = Tactic()
            tactic_entity.name = tactic_name
            tactic_entity.attack_id = tactic_id

            self.session.add(tactic_entity)
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

        self.session.commit()