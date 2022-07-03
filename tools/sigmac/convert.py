# usage:
#   1. set this python file in sigma/tools dir.
#   2. cd sigma/tools dir
#   3. `python3 convert.sh`
import logging
import os
import shutil
import subprocess
from multiprocessing.pool import ThreadPool
from typing import Dict, Set

import ruamel.yaml

FORMAT = ('[%(levelname)-8s] %(name)s, %(lineno)d: %(message)s')
logging.basicConfig(format = FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)

yaml = ruamel.yaml.YAML()
sigma_dir = "/user/sample/sigma" # path to SIGMA's git dir
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
        num = None
        self.threadpool = ThreadPool(num)
        self._convert_rules(self.rules_dir)
        self.threadpool.close()
        self.threadpool.join()

    def _convert_rules(self, rules_dir):
        for file in os.listdir(rules_dir):
            file_path = os.path.join(rules_dir, file)
            if os.path.isdir(file_path):
                self._convert_rules(file_path)
            elif file.endswith(".yml"):
                self.threadpool.apply_async(self.convert_rule_worker, (file_path, file, ))

    def convert_rule_worker(self, rule_path: str, file_name: str):
        with open(rule_path, 'r') as yml:
            rule_data = yaml.load(yml)
            if "logsource" in rule_data and "category" in rule_data["logsource"]:
                category = rule_data["logsource"]["category"]
            elif "service" in rule_data["logsource"]:
                # serviceにsysmonが書かれている場合に対応させる
                # ex. sysmon/sysmon_process_hollowing.yml
                if rule_data["logsource"]["service"] == "sysmon":
                    category = "sysmon_status"
                else:
                    # category = rule_data["logsource"]["service"]
                    logger.info(rule_path + " has no logsoruce.category. This rule has logsoruce.service.")
                    category = None
            else:
                category = None
                logger.warning(rule_path + " has no log category description.")
                return

        logger.debug("target: " + file_name)
        if category in self.config_map:
            configs = copy.deepcopy(self.config_map[category])
        else:
            configs = set()

        tmp = rule_path[len(self.rules_dir)+1:]
        off = tmp.find("/")
        rule_type = tmp[:off]
        path_from_off = tmp[off+1:]

        while True:
            if len(configs) > 0:
                config = configs.pop()
            else:
                config = None

            logger.debug("  config: " + str(config))
            if config == "sysmon.yml":
                output_path = os.path.join(hayabusa_rule_path, rule_type, path_from_off)
            else:
                output_path = os.path.join(hayabusa_rule_path, "builtin", rule_type, path_from_off)

            output_dir = output_path[:-len(file_name)]
            logger.debug("  output_path: " + output_path)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            sigma_command = [
                "python3",
                os.path.join(sigma_dir, sigmac),
                "-t",
                "hayabusa"
            ]
            if config:
                sigma_command.extend(["-c", os.path.join(self.config_dir, config)])
            sigma_command.extend([
                "-c",
                os.path.join(self.config_dir, "windows-services.yml"),
                "--defer-abort",
                rule_path
            ])
            logger.debug("  command: " + str(sigma_command))
            proc = subprocess.Popen(sigma_command, stdout=subprocess.PIPE)
            self.rule_count += 1
            try:
                proc.wait(30)
                with open(output_path, mode="w") as f:
                    f.write(proc.stdout.read().decode("utf-8"))
            except subprocess.TimeoutExpired:
                logger.error("failed to convert " + output_path)
                proc.kill()
            except Exception as err:
                logger.error(err)
            if len(configs) == 0:
                break

if __name__ == "__main__":
    main()
