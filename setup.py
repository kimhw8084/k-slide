"""Include canonical runtime data without maintaining a second source copy."""

from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildWithRuntimeData(build_py):
    def run(self):
        super().run()
        root = Path(__file__).resolve().parent
        destination = Path(self.build_lib) / "k_slide" / "data"
        for directory in ("termbase", "schemas", "prompts", "security"):
            self.copy_tree(str(root / directory), str(destination / directory))
        self.copy_file(str(root / "constraints-production.txt"), str(destination / "constraints-production.txt"))


setup(cmdclass={"build_py": BuildWithRuntimeData})
