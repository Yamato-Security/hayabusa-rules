import argparse
import copy
import fnmatch
import logging
import os
import re
import shutil
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Union, Optional

import oyaml as yaml

FORMAT = '[%(levelname)-2s:%(filename)s:%(lineno)d] %(message)s'
logging.basicConfig(format=FORMAT, level=logging.INFO)
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class LogSource:
    category: Optional[str]
    service: str
    channel: Union[str, list[str]]
    event_id: Optional[Union[int, list[int]]]

    def __hash__(self):
        return hash((self.category, self.service, tuple(self.channel)))

    def get_identifier_for_detection(self, keys: list[str]) -> str:
        new_identifier = ""
        if not self.category:
            new_identifier = self.service.replace("-", "_")
        else:
            new_identifier = self.category.replace("-", "_")
        if any([True for key in keys if key == new_identifier]):
            new_identifier = "logsource_mapping_" + new_identifier
        return new_identifier

    def get_detection(self) -> dict:
        """
        logsourceをdetection用に変換
        """
        if self.event_id:
            return {"Channel": self.channel, "EventID": self.event_id}
        return {"Channel": self.channel}

    def get_condition(self, condition_str, keys: list[str], field_map: dict[str, str]) -> str:
        """
        detectionに追加したlogsourceの条件をconditionにも追加
        """
        if match := re.search(r"([^|].*?)(\s?\| count\(.*)", condition_str):
            # 集計条件はパイプの前までを（）で囲んでand
            cond_before_pipe = f"({self.get_identifier_for_detection(keys)} and {match.group(1)})"
            cond_after_pipe = match.group(2)
            if self.need_field_conversion():
                for field in field_map.keys():
                    cond_after_pipe = cond_after_pipe.replace(field, field_map[field])
            return cond_before_pipe + cond_after_pipe
        if ' ' not in condition_str:
            return f"{self.get_identifier_for_detection(keys)} and {condition_str}"
        return f"{self.get_identifier_for_detection(keys)} and ({condition_str})"

    def need_field_conversion(self):
        if self.category == "process_creation" and self.event_id == 4688:
            return True
        return False


@dataclass(frozen=True)
class LogsourceConverter:
    sigma_path: str
    logsource_map: dict[str, list[LogSource]]
    field_map: dict[str, str]
    sigma_converted: list[tuple[bool, dict]] = field(default_factory=list)

    def transform_field(self, obj: dict, original_field):
        """
        field_mapの内容でfiled名を変換する(category=process_creation以外は変換されない)
        """
        for rewrite_filed in self.field_map.keys():
            if original_field == rewrite_filed:
                obj[self.field_map[original_field]] = obj.pop(original_field)
            elif original_field.startswith(rewrite_filed) and original_field.replace(rewrite_filed, "")[0] == "|":
                new_key = self.field_map[rewrite_filed] + original_field.replace(rewrite_filed, "")
                obj[new_key] = obj.pop(original_field)

    def transform_field_recursive(self, obj: dict) -> dict:
        """
        dictを再帰的に探索し、field_mapの内容でfiled名を変換する(category=process_creation以外は変換されない)
        """
        if isinstance(obj, dict):
            for field_name, val in list(obj.items()):
                self.transform_field(obj, field_name)
                if isinstance(val, dict):
                    self.transform_field_recursive(val)
                elif isinstance(val, list):
                    for item in val:
                        self.transform_field_recursive(item)
        elif isinstance(obj, list):
            for item in obj:
                self.transform_field_recursive(item)
        return obj

    def get_logsources(self, obj: dict) -> list[LogSource]:
        """
        sigmaルールのlogsourceブロックの内容をLogSourceオブジェクトに変換。categoryによっては、複数LogSourceに変換する場合もある
        """
        if 'logsource' not in obj:
            return []
        elif 'service' in obj['logsource']:
            logsources = self.logsource_map.get(obj['logsource']['service'])
            if logsources:
                return logsources
            msg = f"[{self.sigma_path}] has inconvertible service:[{obj['logsource']['service']}].skip conversion."
            LOGGER.warning(msg)
        elif 'category' in obj['logsource']:
            category = obj['logsource']['category']
            logsources = self.logsource_map.get(category)
            if logsources:
                return logsources
            msg = f"[{self.sigma_path}] has inconvertible service:[{category}].skip conversion."
            LOGGER.warning(msg)
        return []

    def convert(self):
        """
        logsourceのcategory/serviceをlogsource_mapに基づき変換し、変換後の内容でdetectionブロックを更新する
        """
        obj = create_obj(self.sigma_path)
        logsources = self.get_logsources(obj)
        if not logsources:
            new_obj = copy.deepcopy(obj)
            new_obj['ruletype'] = 'Sigma'
            self.sigma_converted.append((False, new_obj))
            return  # ログソースマッピングにないcategory/serviceのため、変換処理はスキップ
        for ls in logsources:
            new_obj = copy.deepcopy(obj)
            detection = copy.deepcopy(new_obj['detection'])
            # 出力時に順番を logsource -> selection -> conditionにしたいので一旦クリア
            new_obj['detection'] = dict()
            # detection用に変換したlogsource条件をセット
            new_obj['detection'][ls.get_identifier_for_detection(list(detection.keys()))] = ls.get_detection()
            for key, val in detection.items():
                if re.search(r"\.", key):
                    # Hayabusa側でSearch-identifierにドットを含むルールに対応していないため、変換
                    key = re.sub(r"\.", "_", key)
                if ls.need_field_conversion():
                    # process_creationかつSecurityイベント用ルールのみ、一部フィールド名を変換
                    val = self.transform_field_recursive(val)
                new_obj['detection'][key] = val
            new_obj['detection']['condition'] = ls.get_condition(new_obj['detection']['condition'],
                                                                 list(detection.keys()), self.field_map)
            if ls.need_field_conversion() and "fields" in new_obj:
                fields = new_obj['fields']
                converted_fields = [self.field_map[f] for f in fields if f in self.field_map]
                not_converted_fields = [f for f in fields if f not in self.field_map]
                new_obj['fields'] = converted_fields + not_converted_fields
            new_obj['ruletype'] = 'Sigma'
            condition_str = new_obj['detection']['condition']
            if '%' in condition_str or '->' in condition_str:
                LOGGER.error(f"invalid character [{condition_str}] in [{self.sigma_path}]. skip conversion.")
                continue  # conditionブロックに変な文字が入っているルールがある。この場合スキップ
            if ls.service == "sysmon":
                self.sigma_converted.append((True, new_obj))
            else:
                self.sigma_converted.append((False, new_obj))

    def dump_yml(self, base_dir: str, out_dir: str) -> list[tuple[str, str]]:
        """
        dictをyaml形式のstringに変換する
        """
        res = []
        for is_sysmon, obj in self.sigma_converted:
            output_path = build_out_path(base_dir, out_dir, self.sigma_path, is_sysmon)
            with StringIO() as bs:
                yaml.safe_dump(obj, bs, indent=4, default_flow_style=False)
                res.append((output_path, bs.getvalue()))
        return res


def build_out_path(base_dir: str, out_dir: str, sigma_path: str, sysmon: bool) -> str:
    """
    入力ファイルのパスをもとに、出力用のファイルパスを生成する
    """
    if not base_dir:
        if sysmon:
            return str(Path(out_dir).joinpath(Path("sysmon")).joinpath(Path(sigma_path).name))
        return str(Path(out_dir).joinpath(Path("builtin")).joinpath(Path(sigma_path).name))
    new_path = sigma_path.replace(base_dir, '')
    new_path = new_path.replace('/windows', '')
    new_path = new_path.replace('/builtin', '')
    new_path = new_path.replace('/rules-compliance', '/compliance')
    new_path = new_path.replace('/rules-dfir', '/dfir')
    new_path = new_path.replace('/rules-emerging-threats', '/emerging-threats')
    new_path = new_path.replace('/rules-placeholder', '/placeholder')
    new_path = new_path.replace('/rules-threat-hunting', '/threat-hunting')
    new_path = new_path.replace('/rules', '')
    if sysmon:
        return out_dir + '/sysmon' + new_path
    return out_dir + '/builtin' + new_path


def create_obj(filepath: str) -> dict:
    """
    ymlファイルを読み込み、dictを作成
    """
    if not Path(filepath).exists():
        LOGGER.error(f"file [{filepath}] does not exists.")
        sys.exit(1)
    try:
        with open(filepath) as f:
            return yaml.safe_load(f)
    except Exception as e:
        LOGGER.error(f"Error while loading yml [{filepath}]: {e}")
        sys.exit(1)


def create_field_map(obj: dict) -> dict[str, str]:
    """
    カテゴリcreate_process用のフィールド名をマッピングするdict作成
    """
    if 'fieldmappings' not in obj:
        LOGGER.error("invalid yaml. key[fieldmappings] not found.")
        sys.exit(1)
    field_map = obj['fieldmappings']
    return field_map


def create_service_map(obj: dict) -> dict[str, Union[str, list[str]]]:
    """
    service -> channel をマッピングするdictを作成
    """
    if 'logsources' not in obj:
        LOGGER.error("invalid yaml. key[logsources] not found.")
        sys.exit(1)
    service_to_channel = dict()
    for v in obj['logsources'].values():
        if 'service' in v.keys() and 'conditions' in v.keys():
            service_to_channel[v['service']] = v['conditions']['Channel']
    LOGGER.info("create service map done.")
    return service_to_channel


def create_category_map(obj: dict, service_to_channel: dict[str, Union[str, list[str]]]) -> set[LogSource]:
    """
    category -> channel, event_id マッピングするLogSourceオブジェクトのSetを作成
    """
    if 'logsources' not in obj:
        LOGGER.error("invalid yaml. key[logsources] not found.")
        sys.exit(1)
    mapper = set()
    for v in obj['logsources'].values():
        if 'category' not in v:
            continue
        ls = LogSource(category=v['category'],
                       service=v['rewrite']['service'],
                       channel=service_to_channel[v['rewrite']['service']],
                       event_id=v['conditions']['EventID'])
        mapper.add(ls)
    LOGGER.info("create category map done.")
    return mapper


def merge_category_map(service_map: dict, logsources_lst: list) -> dict[str, list[LogSource]]:
    """
    複数のymlファイルから作成したdictをマージして、categoryをマッピングするための1つのdictを作成
    """
    merged_map = defaultdict(list)
    for logsources in logsources_lst:
        for ls in logsources:
            merged_map[ls.category].append(ls)
    for k, v in service_map.items():
        merged_map[k].append(LogSource(category=None, service=k, channel=v, event_id=None))
    LOGGER.info(f"merge category map done.")
    return merged_map


def find_windows_sigma_rule_files(root: str, rule_pattern: str):
    """
    指定したディレクトリから変換対象のSigmaファイルのファイルパスを取得する
    """
    if Path(root).exists() and Path(root).is_file() and rule_pattern.replace("*", "") in root:
        yield root
    for dirpath, dirnames, filenames in os.walk(root):
        for filename in fnmatch.filter(filenames, rule_pattern):
            filepath = os.path.join(dirpath, filename)
            if not any(target in dirpath for target in ["rule", "deprecated", "unsupported"]):
                continue  # フォルダパスにrule/deprecated/unsupportedがつかないものは、Sigmaルールと関係ないため、除外
            try:
                with open(filepath) as f:
                    data = yaml.safe_load(f)
                if data.get('logsource', {}).get('product') != 'windows':
                    LOGGER.info(f"[{filepath}] has no windows rule. skip conversion.")
                else:
                    yield filepath
            except Exception as e:
                LOGGER.error(f"Error while loading yml [{filepath}]: {e}")


if __name__ == '__main__':
    start_time = time.perf_counter()
    LOGGER.info("Start to logsource mapping sigma rules.")
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", help="Output dir. Default: ./hayabusa_rules", default="./hayabusa_rules")
    parser.add_argument("-r", "--rule_path", help="Target sigma dir or file path.", required=True)
    parser.add_argument("--rule_filter", help="Target file filter. Default: *.yml", default="*.yml")
    args = parser.parse_args()

    if not Path(args.rule_path).exists():
        LOGGER.error(f"Rule directory(file) [{args.rule_path}] does not exists.")
        sys.exit(1)

    if Path(args.output).exists():
        try:
            shutil.rmtree(args.output)
            LOGGER.info(f"Directory [{args.output}] deleted successfully.")
        except OSError as e:
            LOGGER.error(f"Error while deleting directory [{args.output}]: {e}")
            sys.exit(1)

    # category -> channel/event_id 変換のマッピングデータを作成
    service2channel = create_service_map(create_obj("windows-services.yaml"))
    sysmon_map = create_category_map(create_obj('sysmon.yaml'), service2channel)
    win_audit_map = create_category_map(create_obj('windows-audit.yaml'), service2channel)
    win_service_map = create_category_map(create_obj('windows-services.yaml'), service2channel)
    all_category_map = merge_category_map(service2channel, [sysmon_map, win_audit_map, win_service_map])
    process_creation_field_map = create_field_map(create_obj('windows-audit.yaml'))

    # Sigmaディレクトリから対象ファイルをリストアップ
    file_cnt = 0
    for sigma_file in find_windows_sigma_rule_files(args.rule_path, args.rule_filter):
        try:
            lc = LogsourceConverter(sigma_file, all_category_map, process_creation_field_map)
            lc.convert()  # Sigmaルールをマッピングデータにもとづき変換
            base_dir = args.rule_path if Path(args.rule_path).is_dir() else ""
            for out_path, parsed_yaml in lc.dump_yml(base_dir, args.output):  # dictをyml形式の文字列に変換
                p = Path(out_path)
                if not p.parent.exists():
                    os.makedirs(p.parent)
                p.write_text(parsed_yaml)  # 変換後のSigmaルール(yml形式の文字列)をファイルに出力
                file_cnt += 1
                LOGGER.info(f"converted to [{out_path}] done.")
        except Exception as err:
            LOGGER.error(f"Error while converting yml [{sigma_file}]: {err}")
    end_time = time.perf_counter()
    LOGGER.info(f"[{file_cnt}] files conversion finished. converted file was saved under [{args.output}].")
    LOGGER.info(f"Script took [{'{:.2f}'.format(end_time - start_time)}] seconds.")
