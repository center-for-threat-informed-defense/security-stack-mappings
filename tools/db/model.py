from sqlalchemy import Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Mapping(Base):
    __tablename__ = "mapping"
    mapping_id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    path = Column(String, nullable=False, unique=True)
    platform = Column(String, nullable=False)


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
        secondary=tactic_and_technique_xref)


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
    __tablename__ = "mapping_score"
    score_id = Column(Integer, primary_key=True)
    mapping_id = Column("mapping_id", Integer, ForeignKey("mapping.mapping_id"))
    sub_technique_id = Column("sub_technique_id", Integer, 
        ForeignKey("sub_technique.sub_technique_id"))
    score_function = Column(String, nullable=False)
    value = Column(String, nullable=False)