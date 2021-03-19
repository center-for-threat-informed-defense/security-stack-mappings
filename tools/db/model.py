from sqlalchemy import Column, Integer, String, ForeignKey, Table, UniqueConstraint
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


mapping_tag_xref = Table('mapping_tag_xref', Base.metadata,
    Column('mapping_id', Integer, ForeignKey('mapping.mapping_id')),
    Column('tag_id', Integer, ForeignKey('tag.tag_id'))
)


class MappingTechniqueScore(Base):
    __tablename__ = "mapping_technique_score"
    id = Column(Integer, primary_key=True)
    mapping_id = Column(Integer, ForeignKey('mapping.mapping_id'))
    technique_id = Column(Integer, ForeignKey('technique.technique_id'))
    score_id = Column(Integer, ForeignKey('score.score_id', ondelete='CASCADE'))

    __table_args__ = (UniqueConstraint(mapping_id, technique_id, score_id),)
    mapping = relationship("Mapping")
    technique = relationship("Technique")
    score = relationship("Score")

class MappingSubTechniqueScore(Base):
    __tablename__ = "mapping_sub_technique_score"
    id = Column(Integer, primary_key=True)
    mapping_id = Column(Integer, ForeignKey('mapping.mapping_id'), nullable=False)
    sub_technique_id = Column(Integer, ForeignKey('sub_technique.technique_id'), nullable=False)
    score_id = Column(Integer, ForeignKey('score.score_id'), nullable=False)

    __table_args__ = (UniqueConstraint(mapping_id, sub_technique_id, score_id),)
    mapping = relationship("Mapping")
    sub_technique = relationship("SubTechnique")
    score = relationship("Score")


class Mapping(Base):
    __tablename__ = "mapping"
    mapping_id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    path = Column(String, nullable=False, unique=True)
    description = Column(String, nullable=True, unique=False)
    platform = Column(String, nullable=False)
    tags = relationship(
        "Tag",
        secondary=mapping_tag_xref,
        cascade="all,delete",
        backref="mappings")


tactic_and_technique_xref = Table('tactic_technique_xref', Base.metadata,
    Column('tactic_id', Integer, ForeignKey('tactic.tactic_id')),
    Column('technique_id', Integer, ForeignKey('technique.technique_id'))
)


class Tactic(Base):
    __tablename__ = "tactic"
    tactic_id = Column(Integer, primary_key=True)
    attack_id = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False)


class Technique(Base):
    __tablename__ = "technique"
    technique_id = Column(Integer, primary_key=True)
    attack_id = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False, unique=True)
    tactics = relationship(
        "Tactic",
        secondary=tactic_and_technique_xref,
        cascade="all,delete",
        backref="techniques")


class SubTechnique(Base):
    __tablename__ = "sub_technique"
    sub_technique_id = Column(Integer, primary_key=True)
    attack_id = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False)
    # setting unique causes integrity error when inserting sub techniques, why?
    # name = Column(String, nullable=False, unique=True) 
    technique_id = Column(Integer, ForeignKey('technique.technique_id'))
    technique = relationship("Technique")


class Score(Base):
    __tablename__ = "score"
    score_id = Column(Integer, primary_key=True)
    category = Column(String, nullable=False)
    value = Column(String, nullable=False)
    comments = Column(String, nullable=False)


class Tag(Base):
    __tablename__ = "tag"
    tag_id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)