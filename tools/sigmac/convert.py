import os
import shutil
import ruamel.yaml
import logging
from typing import Dict, Set

FORMAT = ('[%(levelname)-8s] %(name)s, %(lineno)d: %(message)s')
logging.basicConfig(format = FORMAT)
logger = logging.getLogger(__name__)

yaml = ruamel.yaml.YAML()
sigma_dir = "."
output_path = "./hayabusa_rules"

def main():
    if os.path.exists(output_path):
        shutil.rmtree(output_path)
    os.mkdir(output_path)
    logconverter = Logconverter(sigma_dir)
    logconverter.create_config_map(os.path.join(sigma_dir, "tools/config/generic/"))
    logconverter.convert_rules(os.path.join(sigma_dir, "rules/windows"))

class Logconverter():
    def __init__(self, sigma_dir: str):
        self.sigma_dir = sigma_dir
        self.config_map: Dict[str, Set[str]] = dict()

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
                    if "category" in config_data["logsources"][logsource]:
                        category = config_data["logsources"][logsource]["category"]
                        if category not in self.config_map:
                            self.config_map[category] = set()
                        self.config_map[category].add(config)

    def convert_rules(self, rules_dir: str):
        for file in os.listdir(rules_dir):
            file_path = os.path.join(rules_dir, file)
            if os.path.isdir(file_path):
                self.convert_rules(file_path)
            elif file.endswith(".yml"):
                self.convert_rule(file_path, file)

    def convert_rule(self, rule_path: str, file_name: str):
        with open(rule_path, 'r') as yml:
            rule_data = yaml.load(yml)
            if "logsource" in rule_data and "category" in rule_data["logsource"]:
                category = rule_data["logsource"]["category"]
            elif "service" in rule_data["logsource"]:
                # category = rule_data["logsource"]["service"]
                logger.info(rule_path + " has no logsoruce.category. This rule has logsoruce.service.")
                category = None
            else:
                category = None
                logger.warning(rule_path + " has no log category description.")
                return

        print("target: " + file_name)
        if category in self.config_map:
            configs = self.config_map[category]
        else:
            configs = {'windows-service.yml'}
        print("       : " + str(configs))

if __name__ == "__main__":
    main()
