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


    def get_root_folder(self):
        return str(Path(os.path.dirname(__file__)).parent.parent)


    def write_visualization(self, output_name, visualization):
        with open(output_name, "w") as f:
            f.write(visualization)


    def output(self, options, mapping_file, visualization):
        output_inline = options["output_inline"]
        if "output_absolute_filename" in options:
            output_name = options["output_absolute_filename"]
        else:
            if output_inline:
                output_dir = os.path.join(mapping_file.parent, self.get_output_folder_name())
                Path(output_dir).mkdir(exist_ok=True)
            else:
                output_dir = options["output_dir"]
        
            file_name = options.get("output_filename", mapping_file.name)
            output_name = os.path.join(output_dir, file_name)
            pre, _ = os.path.splitext(output_name)
            output_name = ".".join([pre, self.get_output_extension()])

        print(f" Generating {output_name}")
        self.write_visualization(output_name, visualization)

        return output_name