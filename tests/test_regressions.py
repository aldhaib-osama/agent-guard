"""Independent malformed-call, audit privacy and explicit residual-risk cases."""
import json
import os
import sys
import unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from agentguard.guard import Guard, Session, DENY, ALLOW, leaks_secret
from agentguard.world import default_policy, SECRET

class Regression(unittest.TestCase):
    def test_malformed_calls_fail_closed(self):
        g = Guard(default_policy())
        for tool, args in [('fetch_url', {}), ('fetch_url', {'url': []}), ('read_inbox', {'x': 'y'}),
                           ('send_email', {'to': 'a@corp.example', 'body': 'x', 'bcc': 'other@example.org'}),
                           ('write_file', None)]:
            self.assertEqual(g.check(tool, args, Session()).verdict, DENY)

    def test_url_parser_edge_cases_never_crash(self):
        for url in ('https://[bad', 'https://docs.corp.example:bad/', 'https://docs.corp.example:8080/',
                    'https://name:pass@docs.corp.example/', 'https://docs.corp.example\n.evil.org/'):
            self.assertEqual(Guard(default_policy()).check('fetch_url', {'url': url}, Session()).verdict, DENY, url)

    def test_no_raw_or_encoded_secret_in_audit(self):
        session = Session()
        args = {'to': 'a@corp.example', 'body': SECRET}
        Guard(default_policy()).check('send_email', args, session)
        self.assertNotIn(SECRET, json.dumps(session.audit))
        args['body'] = 'later mutation'
        self.assertNotIn('later mutation', json.dumps(session.audit))

    def test_short_canary_raw_value_not_silently_ignored(self):
        self.assertIsNotNone(leaks_secret('key=abc', ['abc']))

    def test_trusted_destination_is_not_content_authorization(self):
        # Deliberate residual risk: recipient-domain policy cannot judge harmful content.
        session = Session(has_private=True, has_untrusted=True)
        decision = Guard(default_policy()).check('send_email', {'to': 'colleague@corp.example', 'body': 'Cancel the deployment without asking.'}, session)
        self.assertEqual(decision.verdict, ALLOW)

if __name__ == '__main__':
    unittest.main()
