from unittest import TestCase
from logsource_mapping import *


class TestLogSourceMapper(TestCase):
    def test_create_service_map(self):
        res = create_service_map(create_obj(os.path.dirname(os.path.abspath(__file__)), "windows-services.yaml"))
        self.assertEqual(len(res.keys()), 43)

    def test_create_category_map(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        service_to_channels = create_service_map(create_obj(script_dir, "windows-services.yaml"))
        s1 = create_category_map(create_obj(script_dir, 'sysmon.yaml'), service_to_channels)
        s2 = create_category_map(create_obj(script_dir, 'windows-audit.yaml'), service_to_channels)
        s3 = create_category_map(create_obj(script_dir, 'windows-services.yaml'), service_to_channels)
        s4 = merge_category_map(service_to_channels, [s1, s2, s3])
        self.assertEqual(len(s4), 76)
        self.assertEqual(len(s4["process_creation"]), 2)

    def test_build_out_path(self):
        sigma_path = "/hoge/sigma/builtin/security/sample.yml"
        base_dir = "/hoge/sigma"
        out_dir = "/hoge/hayabusa_rule"
        sysmon = True
        r = build_out_path(base_dir, out_dir, sigma_path, sysmon)
        self.assertEqual(r, "/hoge/hayabusa_rule/sysmon/security/sample.yml")
        sysmon = False
        r = build_out_path(base_dir, out_dir, sigma_path, sysmon)
        self.assertEqual(r, "/hoge/hayabusa_rule/builtin/security/sample.yml")

    def test_get_key(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=1)
        self.assertEqual(ls.get_identifier_for_detection([]), "process_creation")

    def test_get_uniq_key(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=1)
        self.assertEqual(ls.get_identifier_for_detection(["process_creation"]), "logsource_mapping_process_creation")

    def test_get_detection(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        self.assertEqual(ls.get_detection(), {"Channel": "hoge"})

    def test_get_condition(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        self.assertEqual(ls.get_condition("select1 and select2", [], dict()),
                         "process_creation and (select1 and select2)")

    def test_get_single_condition(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        self.assertEqual(ls.get_condition("select", [], dict()), "process_creation and select")

    def test_get_aggregation_condition(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        condition = "select | count(TargetUserName) by Workstation > 10"
        self.assertEqual(ls.get_condition(condition, [], dict()),
                         "(process_creation and select) | count(TargetUserName) by Workstation > 10")

    def test_get_aggregation_conversion_field_condition(self):
        ls = LogSource(category="process_creation", service="Security", channel="hoge", event_id=4688)
        condition = "select | count(Image) by Workstation > 10"
        self.assertEqual(ls.get_condition(condition, [], {"Image": "NewProcessName"}),
                         "(process_creation and select) | count(NewProcessName) by Workstation > 10")

    def test_get_logsources(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        service2channel = create_service_map(create_obj(script_dir, "windows-services.yaml"))
        sysmon_map = create_category_map(create_obj(script_dir, 'sysmon.yaml'), service2channel)
        win_audit_map = create_category_map(create_obj(script_dir, 'windows-audit.yaml'), service2channel)
        win_service_map = create_category_map(create_obj(script_dir, 'windows-services.yaml'), service2channel)
        all_category_map = merge_category_map(service2channel, [sysmon_map, win_audit_map, win_service_map])
        process_creation_field_map = create_field_map("fieldmappings_process", create_obj(script_dir, 'windows-audit.yaml'))
        lc = LogsourceConverter("", all_category_map, process_creation_field_map, [])
        r = lc.get_logsources({"logsource": {"service": "sysmon"}})
        self.assertEqual(r[0].service, "sysmon")

    def test_get_logsources_raise_exception_if_not_supported_category(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        service2channel = create_service_map(create_obj(script_dir, "windows-services.yaml"))
        sysmon_map = create_category_map(create_obj(script_dir, 'sysmon.yaml'), service2channel)
        win_audit_map = create_category_map(create_obj(script_dir, 'windows-audit.yaml'), service2channel)
        win_service_map = create_category_map(create_obj(script_dir, 'windows-services.yaml'), service2channel)
        all_category_map = merge_category_map(service2channel, [sysmon_map, win_audit_map, win_service_map])
        process_creation_field_map = create_field_map("fieldmappings_process", create_obj(script_dir, 'windows-audit.yaml'))
        lc = LogsourceConverter("", all_category_map, process_creation_field_map, [])
        with self.assertRaises(Exception):
            lc.get_logsources({"logsource": {"service": "file_rename"}})

    def test_logsource_validate_security_4688(self):
        ls = LogSource(category="process_creation", event_id=4688, service="", channel="")
        self.assertFalse(ls.is_detectable({"selection": {"Image": "a.exe"}}))
        self.assertFalse(ls.is_detectable({"selection": {"ParentImage": "b.exe"}}))
        self.assertTrue(ls.is_detectable({"selection": {"NewProcessName": "a.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"ParentProcessName": "b.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"NewProcessName|contains": "c.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {'ParentProcessName|endswith': '\\winword.exe', 'NewProcessName|contains': '/l'}, 'condition': 'selection'}))

    def test_logsource_validate_security_4657(self):
        ls = LogSource(category="registry_set", event_id=4657, service="", channel="")
        self.assertFalse(ls.is_detectable({"selection": {"Image": "a.exe"}}))
        self.assertFalse(ls.is_detectable({"selection": {"Details": "foo"}}))
        self.assertTrue(ls.is_detectable({"selection": {"ProcessName": "a.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"SubjectUserName": "foo" }}))
        self.assertTrue(ls.is_detectable({"selection": {"NewValue|contains": "c.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {'OperationType|endswith': '%%1904'}, 'condition': 'selection'}))


    def test_logsource_validate_sysmon_1(self):
        ls = LogSource(category="process_creation", event_id=1, service="", channel="")
        self.assertFalse(ls.is_detectable({"selection": {"NewProcessName": "a.exe"}}))
        self.assertFalse(ls.is_detectable({"selection": {"ParentProcessName": "b.exe"}}))
        self.assertTrue(ls.is_detectable({"selection": {"Image": "a.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"ParentImage": "b.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"Image|contains": "c.exe" }}))
        self.assertTrue(ls.is_detectable({'selection': {'Image|endswith': '\\winword.exe', 'CommandLine|contains': '/l'}, 'condition': 'selection'}))

    def test_logsource_validate_security_12(self):
        ls = LogSource(category="registry_set", event_id=12, service="", channel="")
        self.assertFalse(ls.is_detectable({"selection": {"ProcessName": "a.exe"}}))
        self.assertFalse(ls.is_detectable({"selection": {"NewValue": "foo"}}))
        self.assertTrue(ls.is_detectable({"selection": {"Image": "a.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"Details": "foo" }}))
        self.assertTrue(ls.is_detectable({"selection": {"EventType": "CreateKey" }}))
        self.assertTrue(ls.is_detectable({"selection": {'TargetObject|endswith': 'software'}, 'condition': 'selection'}))

    def test_assign_uuid(self):
        original_uuid = "557e3885-7a7e-40b7-8b69-1e5e658ca1d1"
        inp = {"title": "X", "id": original_uuid, "related": [{"id": "a", "type": "similar"}]}
        res = assign_uuid_for_convert_rules(inp, "abc")
        self.assertEqual(res, {"title":"X", "id": "04428db4-0588-7e14-0c46-c99384f8fc4c", "related": [{'id': 'a', 'type': 'similar'}, {"id": original_uuid, "type": "derived"}]})