from sqlalchemy import create_engine, func, and_, or_
from sqlalchemy.orm import sessionmaker

from db.model import Base, Tactic, Technique, SubTechnique, Mapping, Tag, \
    MappingSubTechniqueScore, MappingTechniqueScore, Score, tactic_and_technique_xref

import yaml

class MappingDatabase:

    def __init__(self, attack_ds):
        self.attack_ds = attack_ds
        self.engine = create_engine(f"sqlite:///mapping.db")
        Base.metadata.create_all(self.engine)
        
        Session = sessionmaker()
        Session.configure(bind=self.engine)
        self.session = Session()


    def init_database(self, mapping_files, tags, skip_attack):
        if skip_attack:
            self.session.query(MappingTechniqueScore).delete()
            self.session.query(MappingSubTechniqueScore).delete()
            self.session.query(Score).delete()
            self.session.query(Mapping).delete()
            self.session.query(Tag).delete()
            self.session.commit()
        else:
            Base.metadata.drop_all(self.engine)
            Base.metadata.create_all(self.engine)
            self.build_attack_database()
        self.build_mapping_database(mapping_files, tags)


    def query_mapping_files(self, tags, relationship, control_names, platforms):
        if tags:
            mapping_entities = self.session.query(Mapping).select_from(Mapping)\
                .join(Mapping.tags).filter(Tag.name.in_(tags)).group_by(Mapping.mapping_id)
            if relationship == "AND":
                mapping_entities = mapping_entities.having(func.count(Tag.tag_id) == len(tags))
        else:
            mapping_entities = self.session.query(Mapping)

        if control_names:
            control_filters = []
            for control in control_names:
                control_filters.append(Mapping.name.like(f"%{control}%"))
            mapping_entities = mapping_entities.filter(and_(or_(*control_filters)))

        if platforms:
            platform_filters = []
            for platform in platforms:
                platform_filters.append(Mapping.platform.like(f"%{platform}%"))
            mapping_entities = mapping_entities.filter(and_(or_(*platform_filters)))

        return mapping_entities


    def get_sub_technique_ids(self, attack_ids):
        ids = []
        for attack_id in attack_ids:
            if "." in attack_id:
                ids.append(attack_id)
            else:
                ids.extend([value[0] for value in self.session.query(SubTechnique.attack_id).\
                    join(Technique).filter(Technique.attack_id == attack_id).all()])
        return ids

    
    def query_mapping_file_scores(self, categories, attack_ids, controls, level, platforms, scores, tactics, tags):
        if level == "Technique":
            sql = self.session.query(Mapping,Technique,Score).select_from(MappingTechniqueScore)\
                .join(Mapping).join(Technique).join(Score).join(tactic_and_technique_xref).join(Tactic)\
                .join(Mapping.tags, isouter=True)
        else:
            sql = self.session.query(Mapping,SubTechnique,Score).select_from(MappingSubTechniqueScore)\
                .join(Mapping).join(SubTechnique).join(Score).join(Technique).join(tactic_and_technique_xref).join(Tactic)\
                .join(Mapping.tags, isouter=True)

        filters = []
        if categories:
            filters.append(Score.category.in_(categories))
        if attack_ids:
            if level == "Technique":
                filters.append(Technique.attack_id.in_(attack_ids))
            else:
                attack_ids = self.get_sub_technique_ids(attack_ids)
                filters.append(SubTechnique.attack_id.in_(attack_ids))
        if controls:
            control_filters = []
            for control in controls:
                control_filters.append(Mapping.name.like(f"%{control}%"))
            filters.append(and_(or_(*control_filters)))
        if platforms:
            platform_filters = []
            for platform in platforms:
                platform_filters.append(Mapping.platform.like(f"%{platform}%"))
            filters.append(or_(*platform_filters))
        if scores:
            filters.append(Score.value.in_(scores))
        if tactics:
            tactics_filters = []
            for tactic in tactics:
                tactics_filters.append(Tactic.name.like(f"%{tactic}%"))
            filters.append(or_(*tactics_filters))
        if tags:
            tags_filters = []
            for tag in tags:
                if tag.startswith('"'):
                    tags_filters.append(Tag.name == tag.replace('"', ""))
                else:
                    tags_filters.append(Tag.name.like(f"%{tag}%"))
            filters.append(or_(*tags_filters))
        
        sql = sql.filter(and_(*filters))

        if level == "Technique":
            return sql.order_by(Mapping.name.asc(), Technique.attack_id.asc())
        else:
            return sql.order_by(Mapping.name.asc(), SubTechnique.attack_id.asc())

    
    def insert_score(self, score_yaml):
        score = Score(category=score_yaml["category"], value=score_yaml["value"], comments=score_yaml.get("comments",""))
        self.session.add(score)
        return score
    

    def insert_technique_score(self, mapping, technique, score):
        mapping_score = MappingTechniqueScore(mapping=mapping,
            technique=technique, score=score)
        self.session.add(mapping_score)


    def insert_sub_technique_score(self, mapping, sub_technique, score):
        mapping_score = MappingSubTechniqueScore(mapping=mapping,
            sub_technique=sub_technique, score=score)
        self.session.add(mapping_score)


    def build_mapping_database(self, mapping_files, tags):
        all_tags = []
        for platform in tags:
            all_tags.extend(tags[platform])
        all_tags = list(set(all_tags))

        for tag in all_tags:
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

            for technique_yaml in mapping_yaml.get("techniques", []):
                technique = self.session.query(Technique).filter(Technique.attack_id == technique_yaml["id"]).first()
                for score_yaml in technique_yaml["technique-scores"]:
                    score = self.insert_score(score_yaml)
                    self.insert_technique_score(mapping_entity, technique, score)

                for sub_technique_score_yaml in technique_yaml.get("sub-techniques-scores", []):
                    for score_yaml in sub_technique_score_yaml["scores"]:
                        score = self.insert_score(score_yaml)
                        for sub_technique_yaml in sub_technique_score_yaml["sub-techniques"]:
                            sub_technique = self.session.query(SubTechnique).\
                                filter(SubTechnique.attack_id == sub_technique_yaml["id"]).first()
                            self.insert_sub_technique_score(mapping_entity, sub_technique, score)


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