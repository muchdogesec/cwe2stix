import os

class VersionManager:
    def __init__(self):
        self.file_system = "stix2_objects"
        self.version_manager = "CWE_VERSION"

    def extract_version_from_file(self, filename: str):

        return filename.replace("cwec_v", "").replace(".xml", "")

    def get_last_version(self):
        if os.path.exists(self.version_manager):
            with open(self.version_manager) as file:
                file_data = file.read()
            return file_data.split("\n")[-1]
        return None

    def update_version_file(self, filename, version_manager=None):
        version = self.extract_version_from_file(filename)
        version_manager = version_manager if version_manager else self.version_manager
        if not os.path.exists(version_manager):
            with open(version_manager, "w") as file:
                file.write(version)

    def is_file_update(self, filename):
        if filename == "":
            return False
        return self.extract_version_from_file(filename) == self.get_last_version()
