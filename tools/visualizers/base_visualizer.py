from abc import ABC, abstractmethod
import os
from pathlib import Path

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
    def visualize(self, mapping_files, options):
        pass


    @abstractmethod
    def get_output_extension(self):
        pass


    @abstractmethod
    def get_output_folder_name(self):
        pass


    def write_visualization(self, output_name, visualization):
        with open(output_name, "w") as f:
            f.write(visualization)


    def output(self, options, mapping_file, visualization):
        output_dir = options["output_dir"]
        output_inline = options["output_inline"]
        if output_inline:
            output_dir = os.path.join(mapping_file.parent, self.get_output_folder_name())
            Path(output_dir).mkdir(exist_ok=True)
        
        output_name = os.path.join(output_dir, mapping_file.name)
        pre, _ = os.path.splitext(output_name)
        output_name = ".".join([pre, self.get_output_extension()])

        print(f" Generating {output_name}")
        self.write_visualization(output_name, visualization)