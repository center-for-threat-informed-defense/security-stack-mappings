from abc import ABC, abstractmethod

class AbstractVisualizer(ABC):

    visualizers = {}

    def __init__(self):
        super().__init__()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.visualizers[cls.get_name()] = cls

    @staticmethod
    @abstractmethod
    def get_name():
        pass

    @abstractmethod
    def visualize(mapping_files, options):
        pass