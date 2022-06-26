import os
import subprocess
import shutil
import ruamel.yaml
import logging
from typing import Dict, Set, List, Any

FORMAT = ('[%(levelname)-8s] %(name)s, %(lineno)d: %(message)s')
logging.basicConfig(format = FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)

yaml = ruamel.yaml.YAML()
sigma_dir = "~/git/sigma"
sigmac = "tools/sigmac"
hayabusa_rule_path = "./hayabusa_rules"

def main():
    if os.path.exists(hayabusa_rule_path):
        shutil.rmtree(hayabusa_rule_path)
    os.mkdir(hayabusa_rule_path)
    logconverter = Logconverter(sigma_dir,
        rules_dir=os.path.join(sigma_dir, "rules/windows"),
        config_dir=os.path.join(sigma_dir, "tools/config/generic/")
    )
    logconverter.create_config_map()
    logconverter.convert_rules()

class Logconverter():
    rule_count = 0

    def __init__(self, sigma_dir: str, rules_dir: str, config_dir: str):
        self.config_map: Dict[str, Set[str]] = dict()

        self.sigma_dir = sigma_dir
        self.rules_dir = rules_dir
        self.config_dir = config_dir

    def create_config_map(self):
        configs = os.listdir(self.config_dir)
        for config in configs:
            if not config.endswith(".yml"):
                continue
            if config == "windows-services.yml":
                continue
            with open(os.path.join(self.config_dir, config), 'r') as yml:
                config_data = yaml.load(yml)
                for logsource in config_data["logsources"]:
                    if "category" in config_data["logsources"][logsource]:
                        category = config_data["logsources"][logsource]["category"]
                        if category not in self.config_map:
                            self.config_map[category] = set()
                        self.config_map[category].add(config)

    def convert_rules(self):
        self.convert_process = []
        # TODO: 呼び出しを並行に
        self._convert_rules(self.rules_dir)
        for (p, output_path) in self.convert_process:
            try:
                p.wait(10)
                with open(output_path, mode="w") as f:
                    for l in p.stdout:
                        l = l.decode("utf-8").strip()
                        f.write(l + '\n')
            except subprocess.TimeoutExpired:
                logger.error("failed to convert " + output_path)
            except Exception as err:
                logger.error(err)

    def _convert_rules(self, rules_dir):
        for file in os.listdir(rules_dir):
            file_path = os.path.join(rules_dir, file)
            if os.path.isdir(file_path):
                self._convert_rules(file_path)
            elif file.endswith(".yml"):
                self._convert_rule(file_path, file)

    def _convert_rule(self, rule_path: str, file_name: str):
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

        logger.debug("target: " + file_name)
        if category in self.config_map:
            configs = self.config_map[category]
        else:
            configs = {}

        tmp = rule_path[len(self.rules_dir)+1:]
        off = tmp.find("/")
        rule_type = tmp[:off]
        path_from_off = tmp[off+1:]

        # TODO: configs[i] に変更する
        if len(configs) > 0:
            for config in configs:
                output_path = os.path.join(hayabusa_rule_path, rule_type + "_" + config[:-4], path_from_off)
                output_dir = output_path[:-len(file_name)]
                logger.debug("  output_path: " + output_path)
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)

                sigma_command = [
                    "python3",
                    os.path.join(sigma_dir, sigmac),
                    "-t",
                    "hayabusa",
                    "-c",
                    os.path.join(self.config_dir, config),
                    "-c",
                    os.path.join(self.config_dir, "windows-services.yml"),
                    "--defer-abort",
                    rule_path
                ]
                logger.debug("  command: " + str(sigma_command))
                proc = subprocess.Popen(sigma_command, stdout=subprocess.PIPE)
                self.convert_process.append((proc, output_path))
                self.rule_count += 1
        else:
            output_path = os.path.join(hayabusa_rule_path, rule_type, path_from_off)
            output_dir = output_path[:-len(file_name)]
            logger.debug("  output_path: " + output_path)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            sigma_command = [
                "python3",
                os.path.join(sigma_dir, sigmac),
                "-t",
                "hayabusa",
                "-c",
                os.path.join(self.config_dir, "windows-services.yml"),
                "--defer-abort",
                rule_path
            ]
            logger.debug("  command: " + str(sigma_command))
            proc = subprocess.Popen(sigma_command, stdout=subprocess.PIPE)
            self.convert_process.append((proc, output_path))
            self.rule_count += 1

if __name__ == "__main__":
    main()
