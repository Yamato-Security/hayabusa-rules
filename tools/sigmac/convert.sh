#!/bin/bash

# Clear current converted rules.
rm -rf hayabusa_rules

# Convert Windows built-in rules with the basic windows-services.yml config file.
if [ -e "rules/windows/builtin" ]; then
  python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/builtin > sigma_to_hayabusa.yml
fi

# Convert non-default Windows built-in rules.
non_build_rules=(
  rules/windows/powershell
  rules/windows/registry_add
  rules/windows/registry_event
  rules/windows/registry_set
  rules/windows/process_creation
)
for rule in ${non_build_rules[@]}; do
  if [ -e $rule ]; then
    python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/windows-audit.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r $rule >> sigma_to_hayabusa.yml
  fi
done

# Convert sysmon rules with sysmon.yml and windows-services.yml.
sysmon_rules=(
  rules/windows/create_remote_thread
  rules/windows/create_stream_hash
  rules/windows/dns_query
  rules/windows/driver_load
  rules/windows/file_delete
  rules/windows/file_event
  rules/windows/image_load
  rules/windows/network_connection
  rules/windows/pipe_created
  rules/windows/process_access
  rules/windows/process_creation
  rules/windows/raw_access_thread
  rules/windows/registry_add
  rules/windows/registry_delete
  rules/windows/registry_event
  rules/windows/registry_set
  rules/windows/sysmon
  rules/windows/wmi_event
)

for rule in ${sysmon_rules[@]}; do
  if [ -e $rule ]; then
    python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r $rule > sigma_to_hayabusa_sysmon.yml
  fi
done

python3 splitter.py

rm sigma_to_hayabusa.yml sigma_to_hayabusa_sysmon.yml
