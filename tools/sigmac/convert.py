from __future__ import annotations

import argparse
import copy
import logging
import os
import shutil
import subprocess
import sys
from multiprocessing.pool import ThreadPool

import ruamel.yaml

#convert.py needs to be run from the sigma directory.
SIGMA_DIR = "./"
SIGMAC_DIR = "./tools/"
EXPORT_DIR_NAME = "./hayabusa_rules"
RULES_DEPRECATED_DIR = "./deprecated/windows"
RULES_DIR = "./rules/windows"
RULES_COMPLIANCE_DIR = "./rules-compliance"
RULES_DFIR_DIR = "./rules-dfir/"
RULES_EMERGING_THREATS_DIR = "./rules-emerging-threats"
RULES_PLACEHOLDER_DIR = "./rules-placeholder/windows"
RULES_THREAT_HUNTING_DIR = "./rules-threat-hunting"
RULES_UNSUPPORTED_DIR = "./unsupported"
CPU = None
IGNORE_CONFIGS = {"windows-services.yml", "powershell.yml"}
EXCLUDE_CATEGORY = {"file_rename"}
SUPPRESSION = False

FORMAT = ('[%(levelname)-8s] %(message)s')
logging.basicConfig(format = FORMAT, level=logging.WARNING)
logger = logging.getLogger(__name__)
yaml = ruamel.yaml.YAML()

def main(rule_folders):
    if os.path.exists(EXPORT_DIR_NAME):
        shutil.rmtree(EXPORT_DIR_NAME)
    os.mkdir(EXPORT_DIR_NAME)
    logconverter = Logconverter(SIGMA_DIR,
        rules_dirs=rule_folders,
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

    def __init__(self, sigma_dir: str, rules_dirs: str, config_dir: str):
        self.config_map: dict[str, set[str]] = dict()

        self.sigma_dir = sigma_dir
        self.rules_dirs = rules_dirs
        self.config_dir = config_dir

    def create_config_map(self):
        configs = os.listdir(self.config_dir)
        for config in configs:
            if not config.endswith(".yaml"):
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
        convert_rule_list = list()
        for rules_dir in self.rules_dirs:
            convert_rule_list.extend(self.create_rule_list(rules_dir))
        print("Converting rules. Please wait.")
        with ThreadPool(CPU) as threadpool:
            result = threadpool.map(sigma_executer, convert_rule_list)
        failed = sum(result)
        print(str(len(result) - failed) + " rules where converted! (failed: " + str(failed) + ")")

    def create_rule_list(self, rules_dir) -> list[ConvertData]:
        convert_datas = list()
        for file in os.listdir(rules_dir):
            file_path = os.path.join(rules_dir, file)
            if os.path.isdir(file_path):
                convert_datas.extend(self.create_rule_list(file_path))
            elif file.endswith(".yml"):
                convert_datas.extend(self.create_convert_command(file_path, file))
        return convert_datas


    @staticmethod
    def create_rule_path(rule_path) -> str:
        rule_path_from_rule_root = rule_path
        if RULES_DEPRECATED_DIR in rule_path:
            rule_path_from_rule_root = rule_path.replace(RULES_DEPRECATED_DIR, "deprecated")
        elif RULES_UNSUPPORTED_DIR in rule_path:
            rule_path_from_rule_root = rule_path.replace(RULES_UNSUPPORTED_DIR, "unsupported")
        elif RULES_COMPLIANCE_DIR in rule_path:
            rule_path_from_rule_root = rule_path.replace(RULES_COMPLIANCE_DIR, "compliance")
        elif RULES_DFIR_DIR in rule_path:
            rule_path_from_rule_root = rule_path.replace(RULES_DFIR_DIR, "dfir")
        elif RULES_EMERGING_THREATS_DIR in rule_path:
            rule_path_from_rule_root = rule_path.replace(RULES_EMERGING_THREATS_DIR, "emerging-threats")
        elif RULES_PLACEHOLDER_DIR in rule_path:
            rule_path_from_rule_root = rule_path.replace(RULES_PLACEHOLDER_DIR, "placeholder")
        elif RULES_THREAT_HUNTING_DIR in rule_path:
            rule_path_from_rule_root = rule_path.replace(RULES_THREAT_HUNTING_DIR, "threat-hunting")
        else:
            rule_path_from_rule_root = rule_path[len(RULES_DIR)+1:] # rm ./rules/windows
        if rule_path_from_rule_root.startswith("builtin/"):
            rule_path_from_rule_root = rule_path_from_rule_root[8:] # rm .builtin
        return rule_path_from_rule_root

    def create_convert_command(self, rule_path: str, file_name: str) -> list[ConvertData]:
        convert_datas: list[ConvertData] = list()
        sysmon_related = False
        category = None

        with open(rule_path, 'r') as yml:
            try:
                rule_data = yaml.load(yml)
            except:
                logger.warning(rule_path + " failed to convert yml.")
                return convert_datas
            if "logsource" in rule_data:
                if "category" in rule_data["logsource"]:
                    category = rule_data["logsource"]["category"]
                if "service" in rule_data["logsource"] and rule_data["logsource"]["service"] == "sysmon":
                    sysmon_related = True
            else:
                logger.warning(rule_path + " has no log category description.")

        logger.debug("target: " + file_name)
        if "logsource" in rule_data:
            if "product" not in rule_data["logsource"]:
                return convert_datas
            elif rule_data["logsource"]["product"] != "windows":
                logger.info(file_name + " has no windows rule.")
                return convert_datas
        if category in EXCLUDE_CATEGORY:
            logger.info(file_name + " has CATEGORY hayabusa couldn't use.")
            return convert_datas
        if category in self.config_map:
            configs = copy.deepcopy(self.config_map[category])
        else:
            configs = set()

        rule_path_from_rule_root = self.create_rule_path(rule_path)

        while True:
            if len(configs) > 0:
                config = configs.pop()
            else:
                config = None

            logger.debug("  config: " + str(config))
            if config == "sysmon.yaml" or sysmon_related == True:
                output_path = os.path.join(EXPORT_DIR_NAME, "sysmon", rule_path_from_rule_root)
            else:
                output_path = os.path.join(EXPORT_DIR_NAME, "builtin", rule_path_from_rule_root)
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
                os.path.join(self.config_dir, "windows-services.yaml"),
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
        outs, errs = proc.communicate(timeout=60)
        logger.info(data.file_name + " were converted.")
        stderr = errs.decode("utf-8")
        if len(stderr) > 0:
            if SUPPRESSION and "An unsupported feature is required for this Sigma rule" in stderr:
                # Suppress Option
                # Do not display warning when converting rules that Hayabusa does not support
                logger.info("Unsupported feature is required for Hayabusa rule. (" + data.file_name + ")")
                return 1
            logger.warning('Conversion of "' + data.file_name + '" failed.\n'
                           'command: ' + str(data.sigma_command) + '\n'
                           + stderr)
            return 1
        with open(data.output_path, mode="w") as f:
            f.write(outs.decode("utf-8"))
    except subprocess.TimeoutExpired:
        logger.error("Timeout Expired, failed to convert " + data.output_path
                    + "\n" + "Command: " + str(data.sigma_command))
        proc.kill()
        return 1
    except Exception as err:
        logger.error(err)
        return 1
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    cpu_num = str(os.cpu_count())
    parser.add_argument("-c", "--cpu",
                        help="You can specify the number of CPUs to use. The default number is " + cpu_num + ".",
                        type=int, default=None)
    parser.add_argument("--rule_path",
                        nargs='*',
                        default=[RULES_DEPRECATED_DIR, RULES_DIR, RULES_COMPLIANCE_DIR, RULES_DFIR_DIR, RULES_EMERGING_THREATS_DIR, RULES_PLACEHOLDER_DIR, RULES_THREAT_HUNTING_DIR, RULES_UNSUPPORTED_DIR],
                        help="""
                        Full path to the rule directory you want to convert.If more than one directory is provided, separate them with a space.
                        """)
    parser.add_argument("-o", "--output",
                        help="Export directory. Default: ./hayabusa_rules",
                        default="./hayabusa_rules")
    parser.add_argument("--debug", help="Debug mode.",
                    action="store_true")
    parser.add_argument("--verbose", help="Show more information",
                    action="store_true")
    parser.add_argument("-s", "--suppression",
                    help="Suppresses errors when converting rules that Hayabusa does not support.",
                    action="store_true")
    args = parser.parse_args()

    files = os.listdir(SIGMAC_DIR)
    if "sigmac" not in files:
        logger.error("Could not find sigmac in this directory. You must place convert.py in the sigma directory.")
        sys.exit(1)
    SIGMAC = os.path.join(SIGMAC_DIR, "sigmac")

    # DEBUG MODE
    if args.debug:
        logger.setLevel(level=logging.DEBUG)
    if args.verbose:
        logger.setLevel(level=logging.INFO)

    # SET ENV
    EXPORT_DIR_NAME = args.output
    CPU = args.cpu
    if args.suppression:
        SUPPRESSION = True

    if args.rule_path:
        for rule_dir in args.rule_path:
            if not os.path.isdir(rule_dir):
                logger.error(rule_dir + " does not exist.")
                sys.exit(1)
    main(args.rule_path)
