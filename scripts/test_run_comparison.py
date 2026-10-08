import argparse
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from scripts.run_comparison import (INSPECT_FORMAT, ROOT, VARIANTS, compose_prefix,
                                    build_parser, comparison_plan, experiment_command,
                                    local_context_endpoint, main, redact_config,
                                    sanitized_logs, validate_args, variant_environment)


class ComparisonConstructionTests(unittest.TestCase):
    def test_comparisons_keep_rpc_control_and_add_independent_backend_baseline(self):
        self.assertEqual(len(VARIANTS), 6)
        self.assertEqual({(envoy, rls, app) for _, envoy, rls, app in VARIANTS},
                         {('off', 'bypass', 'off'), ('adaptive', 'bypass', 'off'),
                          ('rls_adaptive', 'bypass', 'off'), ('rls_adaptive', 'fixed', 'off'),
                          ('rls_adaptive', 'feedback', 'off'), ('off', 'bypass', 'fixed')})

    def test_only_local_socket_context_is_allowed(self):
        local_context_endpoint('unix:///var/run/docker.sock')
        for endpoint in ('ssh://host', 'tcp://127.0.0.1:2375', 'tcp://remote:2375'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                local_context_endpoint(endpoint)

    def test_command_construction_keeps_gateway_seed_and_origin_policy_fixed(self):
        args = build_parser().parse_args([])
        with patch('scripts.run_comparison.python_executable', return_value='/local/python'):
            command = experiment_command(args, 'adaptive-rls-feedback')
        self.assertEqual(command[command.index('--base-url') + 1], 'http://127.0.0.1:8080')
        self.assertEqual(command[command.index('--mode') + 1], 'off')
        self.assertEqual(command[command.index('--seed') + 1], '42')
        self.assertEqual(command[command.index('--seconds') + 1], '30')
        self.assertEqual(command[0], '/local/python')
        prefix = compose_prefix(['docker', '--context', 'desktop-linux', 'compose'])
        self.assertIn(str(ROOT / 'compose.yaml'), prefix)
        self.assertIn('--env-file', prefix)

    def test_backend_baseline_changes_only_admission_mode_for_same_workload(self):
        args = build_parser().parse_args(['--arrival', 'jittered', '--report-rounds', '60',
                                         '--fixed-limit', '1'])
        regular = experiment_command(args, 'comparison')
        baseline = experiment_command(args, 'comparison', 'fixed')
        mode_index = regular.index('--mode') + 1
        self.assertEqual(baseline[mode_index], 'fixed')
        baseline[mode_index] = 'off'
        self.assertEqual(regular, baseline)

    def test_balanced_plan_visits_every_position_and_reuses_seed_within_pair(self):
        args = build_parser().parse_args(['--repeats', '6'])
        plan = comparison_plan(args)
        self.assertEqual(plan, comparison_plan(args))
        for label, *_ in VARIANTS:
            self.assertEqual({row['position'] for row in plan if row['label'] == label}, set(range(6)))
        for repeat in range(6):
            rows = [row for row in plan if row['repeat_index'] == repeat]
            self.assertEqual({row['seed'] for row in rows}, {42 + repeat})
            self.assertEqual({row['round_order'] for row in rows},
                             {'wait-first' if repeat % 2 == 0 else 'cancel-first'})

    def test_cancellation_command_preserves_probe_bounds_and_baseline(self):
        args = build_parser().parse_args(['--workload', 'cancellation', '--seconds', '5',
                                         '--round-order', 'cancel-first', '--arrival', 'burst'])
        command = experiment_command(args, 'backend-fixed', 'fixed')
        self.assertTrue(command[1].endswith('cancellation_probe.py'))
        self.assertNotIn('--scenario', command)
        self.assertEqual(command[command.index('--mode') + 1], 'fixed')
        self.assertEqual(command[command.index('--round-order') + 1], 'cancel-first')
        self.assertEqual(command[command.index('--seed') + 1], '42')

    def test_invalid_workload_limits_fail_before_starting_docker(self):
        for argv in (['--repeats', '0'], ['--repeats', '11'], ['--fixed-limit', '4'],
                     ['--workload', 'cancellation', '--seconds', '31'],
                     ['--report-rounds', '101'], ['--seconds', '121']):
            parser = build_parser()
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                validate_args(parser, parser.parse_args(argv))

    @patch('scripts.run_comparison.discover_docker')
    def test_plan_mode_is_read_only_and_resolves_balanced_round_order(self, discover):
        output = io.StringIO()
        with patch('sys.argv', ['run_comparison.py', '--plan', '--workload', 'cancellation',
                                '--seconds', '5', '--repeats', '2']), contextlib.redirect_stdout(output):
            main()
        plan = json.loads(output.getvalue())
        self.assertEqual(len(plan), 12)
        self.assertEqual({row['round_order'] for row in plan}, {'wait-first', 'cancel-first'})
        for row in plan:
            command = row['command']
            self.assertEqual(command[command.index('--mode') + 1], row['app_mode'])
            self.assertEqual(command[command.index('--round-order') + 1], row['round_order'])
        discover.assert_not_called()

    @patch('scripts.run_comparison.os.getuid', return_value=501)
    @patch('scripts.run_comparison.os.getgid', return_value=20)
    def test_environment_sets_identity_and_modes_without_mutating_input(self, *_):
        base = {'OTHER': 'kept'}
        env = variant_environment(base, 'rls_adaptive', 'feedback')
        self.assertEqual(env['LAB_UID'], '501')
        self.assertEqual(env['LAB_GID'], '20')
        self.assertEqual(env['RLS_MODE'], 'feedback')
        self.assertEqual(base, {'OTHER': 'kept'})

    def test_archived_config_and_inspection_never_contain_environment_values(self):
        config = {'services': {'app': {'environment': {'TOKEN': 'sensitive'}, 'cpus': 1},
                               'db': {'password': 'also-sensitive'}}}
        rendered = json.dumps(redact_config(config))
        self.assertNotIn('sensitive', rendered)
        self.assertIn('cpus', rendered)
        self.assertNotIn('.Config', INSPECT_FORMAT)
        self.assertNotIn('Env', INSPECT_FORMAT)
        self.assertIn('.HostConfig.Memory', INSPECT_FORMAT)

    def test_archived_logs_drop_query_secrets_and_unknown_fields(self):
        raw = '\n'.join([json.dumps({'path': '/api/report?token=secret', 'status': 200, 'token': 'secret'}),
                         json.dumps({'event': 'control_update', 'report_rate': 1}),
                         'unstructured secret output'])
        result = sanitized_logs(raw)
        self.assertNotIn('secret', json.dumps(result))
        self.assertEqual(result['events'][0]['path'], '/api/report')
        self.assertEqual(result['unstructured_lines_omitted'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
