## pip install pyyaml

import os
import ruamel.yaml

yaml = ruamel.yaml.YAML()
path = "./" # import simga_to_hayabusa*.yml file dir

def load_ymls( filepath ):
    with open(filepath) as f:
        return list(yaml.load_all(f))

def dump_yml( filepath, data ):
    with open(filepath, "w") as stream:
        yaml.dump(data, stream )

def main():
    files = os.listdir(path)
    for file in files:
        if not file.startswith("sigma_to_hayabusa"):
            continue
        dir_prefix = file[17:-4]
        loaded_ymls = load_ymls(file)
        for loaded_yml in loaded_ymls:
            if loaded_yml == None:
                continue

            if loaded_yml["yml_path"] == None or len(loaded_yml["yml_path"]) == 0:
                continue

            out_dir = "hayabusa_rules/" + loaded_yml["yml_path"] + dir_prefix
            out_path = out_dir + "/" + loaded_yml["yml_filename"]

            if not os.path.exists(out_dir):
                os.makedirs(out_dir)

            loaded_yml.pop("yml_path")
            loaded_yml.pop("yml_filename")

            dump_yml(out_path,loaded_yml)

if __name__ == "__main__":
    main()
