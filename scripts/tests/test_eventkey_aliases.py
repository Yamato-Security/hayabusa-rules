"""Event-key alias contracts for provider fields that contain spaces."""
import csv
from pathlib import Path
import unittest


class TestEventKeyAliases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[2] / "config" / "eventkey_alias.txt"
        with path.open(newline="", encoding="utf-8") as stream:
            cls.rows = list(csv.DictReader(stream))
        cls.aliases = {row["Alias"]: row["EventKey"] for row in cls.rows}

    def test_aliases_are_unique(self):
        self.assertEqual(len(self.rows), len(self.aliases))

    def test_defender_spaced_fields_resolve(self):
        event = {"Event": {"EventData": {
            "New Value": "new setting", "Old Value": "old setting",
            "Feature Name": "%%886", "NewValue": "Security value",
        }}}
        for alias, expected in [("New_Value", "new setting"), ("Old_Value", "old setting"),
                                ("Feature_Name", "%%886")]:
            with self.subTest(alias=alias):
                value = event
                for part in self.aliases[alias].split("."):
                    value = value[part]
                self.assertEqual(value, expected)

    def test_unrelated_raw_fields_are_not_redirected(self):
        # These names are shared by Security and SMB events. They may be
        # unaliased (recursive lookup) or explicitly name their raw EventData key.
        for field in ("NewValue", "OldValue", "ProcessName", "Address"):
            with self.subTest(field=field):
                expected = f"Event.EventData.{field}"
                self.assertEqual(self.aliases.get(field, expected), expected)


if __name__ == "__main__":
    unittest.main()
