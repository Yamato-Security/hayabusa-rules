from unittest import TestCase
from logsource_mapping import *


class TestLogSourceMapper(TestCase):
    def test_create_service_map(self):
        res = create_service_map(create_obj("windows-services.yaml"))
        self.assertEquals(len(res.keys()), 35)

    def test_create_category_map(self):
        service_to_channels = create_service_map(create_obj("windows-services.yaml"))
        s1 = create_category_map(create_obj('sysmon.yaml'), service_to_channels)
        s2 = create_category_map(create_obj('windows-audit.yaml'), service_to_channels)
        s3 = create_category_map(create_obj('windows-services.yaml'), service_to_channels)
        s4 = merge_category_map(service_to_channels, [s1, s2, s3])
        self.assertEquals(len(s4), 65)
        self.assertEquals(len(s4["process_creation"]), 2)

    # def test_logsource_converter(self):
    #     service_to_channels = create_service_map(create_obj("windows-services.yaml"))
    #     s1 = create_category_map(create_obj('sysmon.yaml'), service_to_channels)
    #     s2 = create_category_map(create_obj('windows-audit.yaml'), service_to_channels)
    #     s3 = create_category_map(create_obj('windows-services.yaml'), service_to_channels)
    #     s4 = merge_category_map(service_to_channels, [s1, s2, s3])
    #     f1 = create_field_map(create_obj('windows-audit.yaml'))
    #     lc = LogsourceConverter("proc_creation_win_7zip_exfil_dmp_files.yml", s4, f1)
    #     lc.convert()
    #     self.assertEquals(len(lc.sigma_converted), 2)

    def test_build_out_path(self):
        sigma_path = "/hoge/sigma/builtin/security/sample.yml"
        base_dir = "/hoge/sigma"
        out_dir = "/hoge/hayabusa_rule"
        sysmon = True
        r = build_out_path(base_dir, out_dir, sigma_path, sysmon)
        self.assertEquals(r, "/hoge/hayabusa_rule/sysmon/security/sample.yml")
        sysmon = False
        r = build_out_path(base_dir, out_dir, sigma_path, sysmon)
        self.assertEquals(r, "/hoge/hayabusa_rule/builtin/security/sample.yml")

    def test_get_key(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=1)
        self.assertEquals(ls.get_identifier_for_detection(), "process_creation")

    def test_get_detection(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        self.assertEquals(ls.get_detection(), {"Channel": "hoge"})

    def test_get_condition(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        self.assertEquals(ls.get_condition("select1 and select2"), "process_creation and (select1 and select2)")

    def test_get_single_condition(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        self.assertEquals(ls.get_condition("select"), "process_creation and select")

    def test_get_aggregation_condition(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        condition = "select | count(TargetUserName) by Workstation > 10"
        self.assertEquals(ls.get_condition(condition),
                          "(process_creation and select) | count(TargetUserName) by Workstation > 10")
