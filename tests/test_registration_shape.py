"""Offline mapping contract; fixture results are not live CloudAppEvents evidence."""
import json
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]

class RegistrationShapeTests(unittest.TestCase):
    def test_documented_target_identity_is_guarded_and_never_taken_from_upn(self):
        query=(ROOT/'kql/defender-xdr/03-device-registration-after-device-code.kql').read_text()
        self.assertIn('RegistrationUserObjectId = tolower(tostring(RawEventData.Target[1].ID))',query)
        self.assertNotIn('RegistrationUserObjectId = tolower(tostring(RawEventData.ObjectId))',query)
        self.assertIn('on $left.RegistrationUserObjectId == $right.AccountObjectId',query)
        action=re.search(r'where ActionType =~ "([^"]+)"',query)[1]
        service=re.search(r'where AccountDisplayName =~ "([^"]+)"',query)[1]
        pattern=re.search(r'RegistrationUserObjectId matches regex @"([^"]+)"',query)[1]
        nil=re.search(r'RegistrationUserObjectId != "([^"]+)"',query)[1]
        cases=json.loads((ROOT/'tests/fixtures/device-registration-shape.json').read_text())
        self.assertGreaterEqual(len(cases),10)
        for case in cases:
            target=case['target']
            candidate=str(target[1].get('ID','')).lower() if len(target)>1 else ''
            actual=candidate if (case['action'].lower()==action.lower() and case['service'].lower()==service.lower()
                                  and re.fullmatch(pattern,candidate) and candidate!=nil) else None
            with self.subTest(case=case['name']):self.assertEqual(actual,case['expected'])

if __name__=='__main__':unittest.main()
