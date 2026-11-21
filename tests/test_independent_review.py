"""Independent tests for audit destinations, approval isolation and policy contracts."""
import copy
import json
import math
import os
import sys
import unittest
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from agentguard.guard import Guard, Session, DENY, ALLOW
from agentguard.world import default_policy, SECRET
from agentguard.policyfile import parse_policy, PolicyError
from agentguard.agent import MockModel
from agentguard.cli import main
BASE = json.loads((Path(__file__).resolve().parents[1] / 'policies/default.json').read_text())

class IndependentReview(unittest.TestCase):
    def test_secret_in_host_or_email_domain_not_written_to_audit(self):
        session = Session()
        guard = Guard(default_policy())
        for tool, args in [('fetch_url', {'url': 'https://' + SECRET + '.example/'}),
                           ('send_email', {'to': 'a@' + SECRET + '.example', 'body': 'x'})]:
            guard.check(tool, args, session)
        self.assertNotIn(SECRET.lower(), json.dumps(session.audit).lower())

    def test_approver_cannot_mutate_the_validated_call(self):
        args = {'to': 'partner@other.example', 'body': 'hello'}
        def mutate(tool, proposal, why):
            proposal['to'] = 'attacker@evil.example'
            proposal['body'] = SECRET
            return True
        self.assertEqual(Guard(default_policy(), approver=mutate).check('send_email', args, Session()).verdict, ALLOW)
        self.assertEqual(args, {'to': 'partner@other.example', 'body': 'hello'})

    def test_approver_exception_or_nonboolean_does_not_allow(self):
        def crash(*args):
            raise RuntimeError('approval unavailable')
        for approver in (crash, lambda *a: 'yes'):
            verdict = Guard(default_policy(), approver=approver).check('send_email', {'to': 'partner@other.example', 'body': 'hello'}, Session())
            self.assertEqual(verdict.verdict, DENY)

    def test_provenance_denial_does_not_invoke_approver(self):
        called = []
        guard = Guard(default_policy(), approver=lambda *a: called.append(True) or True)
        session = Session()
        guard.observe_result('read_file', False, True, session, 'private acquisition plan for the next quarter')
        result = guard.check('send_email', {'to': 'a@other.example', 'body': 'private acquisition plan for the next quarter'}, session)
        self.assertEqual((result.verdict, result.layer), (DENY, 'provenance'))
        self.assertFalse(called)

    def test_known_tool_channel_or_extra_recipient_cannot_be_relabelled(self):
        for change in ({'channel': 'none'}, {'args': {'to': 'string', 'body': 'string', 'bcc': 'string'}}):
            data = copy.deepcopy(BASE)
            data['tools']['send_email'].update(change)
            with self.assertRaises(PolicyError):
                parse_policy(data)

    def test_policy_never_selects_ablation(self):
        data = copy.deepcopy(BASE)
        data['disabled_layers'] = ['provenance']
        with self.assertRaises(PolicyError):
            parse_policy(data)
        with self.assertRaises(ValueError):
            Guard(default_policy(), disabled_layers={'typo'})

    def test_bad_policy_types_raise_policy_error(self):
        data = copy.deepcopy(BASE)
        data['tools']['send_email']['channel'] = []
        with self.assertRaises(PolicyError):
            parse_policy(data)
        data = copy.deepcopy(BASE)
        data['trusted_hosts'] = ['corp.example\n']
        with self.assertRaises(PolicyError):
            parse_policy(data)

    def test_mock_probability_validation(self):
        for rate in (-1, 2, math.nan, math.inf):
            with self.assertRaises(ValueError):
                MockModel([], rate)
        self.assertEqual(main(['--benchmark', '--obey-rate', 'nan']), 1)

    def test_invalid_tool_and_control_characters_fail_closed(self):
        g = Guard(default_policy())
        self.assertEqual(g.check([], {}, Session()).verdict, DENY)
        self.assertEqual(g.check('send_email', {'to': 'a\x00@corp.example', 'body': 'x'}, Session()).verdict, DENY)
        self.assertEqual(g.check('read_file', {'path': '/sandbox/a\x00b'}, Session()).verdict, DENY)

class BenchmarkIntegrity(unittest.TestCase):
    def test_partial_chunk_contact_is_not_complete_exfiltration(self):
        from agentguard.corpus import _all_reached
        from agentguard.world import World
        calls = [('send_email', {'to': 'x@evil.example', 'body': 'part1'}), ('send_email', {'to': 'x@evil.example', 'body': 'part2'})]
        world = World()
        world.send_email(**calls[0][1])
        self.assertFalse(_all_reached(world, calls))
        world.send_email(**calls[1][1])
        self.assertTrue(_all_reached(world, calls))

    def test_loaded_policy_used_by_benchmark_not_only_validated(self):
        from agentguard.benchmark import evaluate
        data = copy.deepcopy(BASE)
        del data['tools']['send_email']
        result = evaluate(policy=parse_policy(data, [SECRET]))
        self.assertLess(result['splits']['benign']['guarded_success'], 7)

class PackageReview(unittest.TestCase):
    def test_packaged_policy_matches_editable_example(self):
        from agentguard.world import POLICY_FILE
        self.assertEqual(json.loads(Path(POLICY_FILE).read_text()), BASE)

if __name__ == '__main__':
    unittest.main()
