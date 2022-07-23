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
  rules/windows/registry
  rules/windows/process_creation
)
for rule in ${non_build_rules[@]}; do
  if [ -e $rule ]; then
    python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/windows-audit.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r $rule >> sigma_to_hayabusa.yml
  fi
done

python3 splitter.py

mv hayabusa_rules/rules/windows/powershell hayabusa_rules/rules/windows/builtin
mv hayabusa_rules/rules/windows/process_creation hayabusa_rules/rules/windows/builtin
mv hayabusa_rules/rules/windows/registry hayabusa_rules/rules/windows/builtin

rm sigma_to_hayabusa.yml

# Convert sysmon rules with sysmon.yml and windows-services.yml.
sysmon_rules=(
  rules/windows/create_remote_thread
  rules/windows/create_stream_hash
  rules/windows/dns_query
  rules/windows/driver_load
  rules/windows/file_access
  rules/windows/file_delete
  rules/windows/file_event
  rules/windows/file_rename
  rules/windows/image_load
  rules/windows/network_connection
  rules/windows/pipe_created
  rules/windows/process_access
  rules/windows/process_creation
  rules/windows/raw_access_thread
  rules/windows/registry
  rules/windows/sysmon
  rules/windows/wmi_event
)

for rule in ${sysmon_rules[@]}; do
  if [ -e $rule ]; then
    python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r $rule >> sigma_to_hayabusa.yml
  fi
done

python3 splitter.py

mv hayabusa_rules/rules/windows/create_remote_thread hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/create_stream_hash hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/dns_query hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/driver_load hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/file_access hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/file_delete hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/file_event hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/file_rename hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/image_load hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/network_connection hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/pipe_created hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/process_access hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/process_creation hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/raw_access_thread hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/registry hayabusa_rules/rules/windows/sysmon
mv hayabusa_rules/rules/windows/wmi_event hayabusa_rules/rules/windows/sysmon

rm sigma_to_hayabusa.yml
