import pkgutil
import inspect

from visualizers.base_visualizer import AbstractVisualizer

class VisualizersCollection:

    visualizers = {}

    def __init__(self):
        self.reload_plugins()

    def reload_plugins(self):
        self.walk_packages()

    def walk_packages(self):
        packages = __import__("visualizers")

        for _, visualizer_name, is_pkg in pkgutil.iter_modules(packages.__path__, packages.__name__ + '.'):
            if not is_pkg:
                visualizer_module = __import__(visualizer_name, fromlist=['*'])
                class_mems = inspect.getmembers(visualizer_module, inspect.isclass)
                for (_, aclass) in class_mems:
                    if issubclass(aclass, AbstractVisualizer) and (aclass is not AbstractVisualizer):
                        vname = aclass.get_name()
                        if vname in self.visualizers:
                            raise ValueError(f"Visualizer with name {vname} already exists!")
                        self.visualizers[aclass.get_name()] = aclass