# usage:
#   1. set this python file in sigma/tools dir.
#   2. cd sigma/tools dir
#   3. `python3 convert.sh`
import argparse
import copy
import logging
import os
import shutil
import subprocess
from multiprocessing.pool import ThreadPool
from typing import Dict, List, Set

import ruamel.yaml

FORMAT = ('[%(levelname)-8s] %(name)s, %(lineno)-3d: %(message)s')
logging.basicConfig(format = FORMAT, level=logging.WARNING)
logger = logging.getLogger(__name__)

yaml = ruamel.yaml.YAML()
sigma_dir = "/user/sample/sigma" # path to SIGMA's git dir
sigmac = "tools/sigmac"
export_dir_name = "./hayabusa_rules"

def main():
    if os.path.exists(export_dir_name):
        shutil.rmtree(export_dir_name)
    os.mkdir(export_dir_name)
    logconverter = Logconverter(sigma_dir,
        rules_dir=os.path.join(sigma_dir, "rules/windows"),
        config_dir=os.path.join(sigma_dir, "tools/config/generic/")
    )
    logconverter.create_config_map()
    converted_rules = logconverter.convert_rules()
    print(str(converted_rules) + " rules where converted!")

class ConvertData(object):
    __slots__ = [
        'file_name',    # 変換対象ファイル
        'output_path',  # 変換出力先
        'sigma_command' # 変換コマンド
    ]
    
    def __init__(self, file_name, output_path, sigma_command):
        self.file_name = file_name
        self.output_path = output_path
        self.sigma_command = sigma_command

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

    def convert_rules(self) -> int:
        num = None
        convert_rule_list =self.create_rule_list(self.rules_dir)
        print("convert called!")
        with ThreadPool(num) as threadpool:
            print(threadpool.map(sigma_executer, convert_rule_list))
        return self.rule_count

    def create_rule_list(self, rules_dir) -> List[ConvertData]:
        convert_datas = list()
        for file in os.listdir(rules_dir):
            file_path = os.path.join(rules_dir, file)
            if os.path.isdir(file_path):
                convert_datas.extend(self.create_rule_list(file_path))
            elif file.endswith(".yml"):
                convert_datas.extend(self.create_convert_command(file_path, file))
        return convert_datas

    def create_convert_command(self, rule_path: str, file_name: str) -> List[ConvertData]:
        convert_datas: List[ConvertData] = list()
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
                output_path = os.path.join(export_dir_name, rule_type, path_from_off)
            else:
                output_path = os.path.join(export_dir_name, "builtin", rule_type, path_from_off)
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
            convert_datas.append(ConvertData(file_name, output_path, sigma_command))
            if len(configs) == 0:
                break
        return convert_datas

def sigma_executer(data: ConvertData):
    """実際にSigmacを実行する関数。
    Args:
        sigma_command (_type_): _description_
        file_name (_type_): _description_
        output_path (_type_): _description_
    """
    proc = subprocess.Popen(data.sigma_command, stdout=subprocess.PIPE)
    try:
        proc.wait(30)
        logger.info(data.file_name + " were converted.")
        with open(data.output_path, mode="w") as f:
            f.write(proc.stdout.read().decode("utf-8"))
    except subprocess.TimeoutExpired:
        logger.error("failed to convert " + data.output_path)
        proc.kill()
        return 1
    except Exception as err:
        logger.error(err)
        return 1
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--sigma_dir", help="path to sigma's git dir")
    parser.add_argument("-c", "--cpu",
                        help="You can specify the number of CPUs to use. Deault is os.cpu_count()'s number",
                        default=None)
    parser.add_argument("-r", "--rule_path",
                        help="""
                        full path to rule you want to convert.
                        ex.> python3 convert.py -r /path/to/ruledir
                        """)
    parser.add_argument("-o",
                        help="Export dir. Default: ./hayabusa_rules",
                        default="hayabusa_rules")
    parser.add_argument("--debug", help="Debug mode.",
                    action="store_true")
    parser.add_argument("--verbose", help="Show more information",
                    action="store_true")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(level=logging.DEBUG)
    if args.verbose:
        logger.setLevel(level=logging.INFO)

    main()
