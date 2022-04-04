# Clear current converted rules.
rm -rf hayabusa_rules

# Convert Windows built-in rules with the basic windows-services.yml config file.
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/builtin > sigma_to_hayabusa.yml

# Convert non-default Windows built-in rules.
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/windows-audit.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/powershell >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/windows-audit.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/registry_add >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/windows-audit.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/registry_event >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/windows-audit.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/registry_set >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/windows-audit.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/process_creation >> sigma_to_hayabusa.yml

# Convert sysmon rules with sysmon.yml and windows-services.yml.
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/create_remote_thread >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/create_stream_hash >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/dns_query >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/driver_load >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/file_delete >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/file_event >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/image_load >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/network_connection >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/pipe_created >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/process_access >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/process_creation >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/raw_access_thread >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/registry_add >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/registry_delete >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/registry_event >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/registry_set >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/sysmon >> sigma_to_hayabusa.yml
python3 ./tools/sigmac -t hayabusa -c ./tools/config/generic/sysmon.yml -c ./tools/config/generic/windows-services.yml --defer-abort -r rules/windows/wmi_event >> sigma_to_hayabusa.yml

python3 splitter.py