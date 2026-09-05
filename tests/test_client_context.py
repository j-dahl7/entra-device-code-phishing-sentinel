"""Independent expected-case decisions plus tracked KQL contracts, not a KQL engine."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ClientContextTests(unittest.TestCase):
    def test_correlated_rule_and_replay_have_no_public_client_suppression(self):
        for name in ("sentinel/01-device-code-50199-to-success.kql", "sample-data/device-code-phishing-replay.kql"):
            with self.subTest(name=name):
                source = (ROOT / "kql" / name).read_text(encoding="utf-8")
                self.assertNotIn("ApprovedDeviceCodeAppIds", source)
                self.assertNotRegex(source, r"(?m)^\| where .*AppId")
                self.assertIn("join kind=inner Successes on UserKey, CorrelationId", source)
                self.assertIn("where SuccessTime between (InterruptTime .. InterruptTime + Window)", source)

    def test_context_query_requires_all_three_keys_and_explicit_clear_risk(self):
        source = (ROOT / "kql/sentinel/02-unapproved-device-code-client.kql").read_text(encoding="utf-8")
        self.assertNotIn("ApprovedDeviceCodeAppIds", source)
        self.assertRegex(source, r"let ApprovedDeviceCodeContexts = datatable\(ApprovedAppId:string, ApprovedUserId:string, ApprovedIPAddress:string\)\[\];")
        self.assertIn("$left.NormalizedAppId == $right.ApprovedAppId", source)
        self.assertIn("$left.ImmutableUserId == $right.ApprovedUserId", source)
        self.assertIn("$left.NormalizedIPAddress == $right.ApprovedIPAddress", source)
        self.assertIn('RiskDuring =~ "none" and RiskAggregated =~ "none"', source)
        self.assertIn('RecordedRiskState in~ ("none", "confirmedSafe", "remediated", "dismissed")', source)
        self.assertIn("| where isempty(ApprovedAppId) or not(RiskContextClear)", source)
        self.assertNotRegex(source, r"(?m)^\| where .*AppDisplayName")
        self.assertIn('ImmutableUserId = tolower(tostring(column_ifexists("UserId", "")))', source)
        # Risk context must survive both the direct event and correlated success paths.
        self.assertEqual(source.count("AppDisplayName, AppId, RiskContextClear;"), 3)
        self.assertIn('column_ifexists("RiskLevelDuringSignIn", "")', source)
        self.assertIn('column_ifexists("RiskLevelAggregated", "")', source)
        self.assertIn('column_ifexists("RiskState", "")', source)
        self.assertIn("InterruptRiskContextClear = RiskContextClear", source)
        self.assertIn("RiskContextClear = RiskContextClear and InterruptRiskContextClear", source)

    def test_expected_context_decisions_include_approved_client_anomalies(self):
        fixture = json.loads((ROOT / "tests/fixtures/device-code-context.json").read_text(encoding="utf-8"))
        # Explicit reviewed policy cases are separate from the source contract.
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                exact = any(all(case[key] and case[key].lower() == approved[key].lower()
                                for key in ("app", "user", "ip")) for approved in fixture["approved"])
                clear = (case["during"] == case["aggregated"] == "none" and
                         case["state"] in {"none", "confirmedSafe", "remediated", "dismissed"})
                if "interruptClear" in case:
                    clear = clear and case["interruptClear"]
                self.assertEqual(not (exact and clear), case["emit"])


if __name__ == "__main__":
    unittest.main()
