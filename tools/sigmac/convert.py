import argparse
import copy
import logging
import os
import shutil
import subprocess
import sys
from multiprocessing.pool import ThreadPool
from typing import Dict, List, Set

import ruamel.yaml

SIGMA_DIR = ".../path/to/sigma/"
SIGMAC = ".../path/to/sigma/tools/sigmac"
EXPORT_DIR_NAME = "./hayabusa_rules"
RULES_DIR = ".../path/to/sigma/rules/windows"
CPU = None
IGNORE_CONFIGS = ["windows-services.yml", "powershell.yml"]

FORMAT = ('[%(levelname)-8s] %(message)s')
logging.basicConfig(format = FORMAT, level=logging.WARNING)
logger = logging.getLogger(__name__)
yaml = ruamel.yaml.YAML()

def main():
    if os.path.exists(EXPORT_DIR_NAME):
        shutil.rmtree(EXPORT_DIR_NAME)
    os.mkdir(EXPORT_DIR_NAME)
    logconverter = Logconverter(SIGMA_DIR,
        rules_dir=RULES_DIR,
        config_dir=os.path.join(SIGMA_DIR, "tools/config/generic/")
    )
    logconverter.create_config_map()
    logconverter.convert_rules()

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
            if config in IGNORE_CONFIGS:
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
        convert_rule_list =self.create_rule_list(self.rules_dir)
        print("convert start!")
        with ThreadPool(CPU) as threadpool:
            result = threadpool.map(sigma_executer, convert_rule_list)
        failed = sum(result)
        print(str(len(result) - failed) + " rules where converted! (failed: " + str(failed) + ")")

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
        sysmon_related = False
        category = None

        with open(rule_path, 'r') as yml:
            rule_data = yaml.load(yml)
            if "logsource" in rule_data:
                if "category" in rule_data["logsource"]:
                    category = rule_data["logsource"]["category"]
                if "service" in rule_data["logsource"] and rule_data["logsource"]["service"] == "sysmon":
                    sysmon_related = True
            else:
                logger.warning(rule_path + " has no log category description.")

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
            if config == "sysmon.yml" or sysmon_related == True:
                output_path = os.path.join(EXPORT_DIR_NAME, "sysmon", rule_type, path_from_off)
            else:
                output_path = os.path.join(EXPORT_DIR_NAME, rule_type, path_from_off)
            output_dir = output_path[:-len(file_name)]
            logger.debug("  output_path: " + output_path)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            sigma_command = [
                "python3",
                SIGMAC,
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
    """
    Args:
        sigma_command (list[str]): convert command for sigma
        file_name (str): target rule file path
        output_path (str): output file path.
    """
    proc = subprocess.Popen(data.sigma_command,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        proc.wait(30)
        logger.info(data.file_name + " were converted.")
        stderr = proc.stderr.read().decode("utf-8")
        if len(stderr) > 0:
            logger.warning('convert "' + data.file_name + '" failed.\n'
                           'command: ' + str(data.sigma_command) + '\n'
                           + stderr)
            return 1
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
    parser.add_argument("-c", "--cpu",
                        help="You can specify the number of CPUs to use. Deault is os.cpu_count()'s number",
                        type=int, default=None)
    parser.add_argument("-r", "--rule_path",
                        help="""
                        full path to rule dir you want to convert.
                        Default: .../sigma/rules/windows/
                        """)
    parser.add_argument("-o", "--output",
                        help="Export dir. Default: ./hayabusa_rules",
                        default="./hayabusa_rules")
    parser.add_argument("--debug", help="Debug mode.",
                    action="store_true")
    parser.add_argument("--verbose", help="Show more information",
                    action="store_true")
    args = parser.parse_args()

    # CHECK DIR
    convertpy_path = os.path.abspath(__file__) # Expect: .../sigma/tools/convert.py
    files = os.listdir(os.path.dirname(convertpy_path))
    if "sigmac" not in files:
        logger.error("sigmac does not exist in same dir. You must set convert.py to sigma/tools dir.")
        sys.exit(1)
    SIGMAC = os.path.join(os.path.dirname(convertpy_path), "sigmac")
    SIGMA_DIR = os.path.abspath(os.path.join(os.path.dirname(convertpy_path), ".."))

    # DEBUG MODE
    if args.debug:
        logger.setLevel(level=logging.DEBUG)
    if args.verbose:
        logger.setLevel(level=logging.INFO)

    # SET ENV
    EXPORT_DIR_NAME = args.output
    CPU = args.cpu
    RULES_DIR = os.path.join(SIGMA_DIR, "rules/windows")
    if args.rule_path:
        RULES_DIR = args.rule_path
        if not os.path.isdir(RULES_DIR):
            logger.error(args.rule_path + " does not exist.")
            sys.exit(1)

    main()
