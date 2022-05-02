import os
import shutil
import ruamel.yaml
from typing import Dict, List

yaml = ruamel.yaml.YAML()
sigma_dir = "../../../sigma"
output_path = "./hayabusa_rules"

def main():
    if os.path.exists(output_path):
        shutil.rmtree(output_path)
    os.mkdir(output_path)
    logconverter = Logconverter(sigma_dir)
    logconverter.create_config_map(os.path.join(sigma_dir, "tools/config/generic/"))

class Logconverter():
    def __init__(self, sigma_dir: str):
        self.sigma_dir = sigma_dir
        self.config_map: Dict[str, List[str]] = dict()

    def create_config_map(self, config_path: str):
        configs = os.listdir(config_path)
        for config in configs:
            if not config.endswith(".yml"):
                continue
            if config == "windows-service.yml":
                continue
            with open(os.path.join(config_path, config), 'r') as yml:
                config_data = yaml.load(yml)
                for logsource in config_data["logsources"]:
                    if "category" in config_data['logsources'][logsource]:
                        category = config_data['logsources'][logsource]["category"]
                        if category not in self.config_map:
                            self.config_map[category] = list()
                        self.config_map[category] += [config]

        print(self.config_map)



if __name__ == "__main__":
    main()
