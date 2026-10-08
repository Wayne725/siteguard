import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from summarize_results import evidence_flags, load_runs, paired_differences, render_report


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding='utf-8')


def group(planned=10, successes=10, rejected=0):
    return {'planned': planned, 'issued': planned, 'generator_drops': 0,
            'business_successes': successes, 'success_within_deadline': successes,
            'http_429': rejected, 'http_5xx': 0, 'client_timeouts': 0}


class ReportingTests(unittest.TestCase):
    def test_cancellation_shared_gateway_state_is_an_explicit_limit(self):
        self.make_run('gateway-off', cancellation=True)
        runs = load_runs(self.root)
        for run in runs:
            run['metadata'].update(base_url='http://127.0.0.1:8080',
                                   gateway_state_shared_between_rounds=True)
            self.assertIn('共用 Envoy 控制器狀態', ' '.join(evidence_flags(run)))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        write_json(self.root / 'manifest.json', {'variants': ['gateway-off', 'backend-fixed']})

    def make_run(self, label, *, cancellation=False, feedback=False, old=False,
                 source='source-a', host_cpus=2, schedule_offset=1, fixed_limit=2,
                 repeat_index=0, report_successes=10, overlapping=0):
        variant_dir = self.root / f'repeat-{repeat_index}' / label
        if not old:
            write_json(variant_dir / 'manifest.json', {
                'label': label, 'status': 'complete', 'repeat_index': repeat_index,
                'rls_mode': 'feedback' if feedback else 'bypass',
                'source_sha256': {'server.py': source},
                'containers': {'app': {'nano_cpus': 1_000_000_000, 'memory_bytes': 500}},
                'host_resources': {'cpus': host_cpus, 'memory_bytes': 2000, 'architecture': 'arm64', 'os': 'linux'}})
        data_dir = variant_dir / 'experiment' / 'run'
        data_dir.mkdir(parents=True, exist_ok=True)
        schedule = [{'offset_s': schedule_offset, 'kind': 'orders'}]
        write_json(data_dir / 'schedule.json', schedule)
        write_json(data_dir / 'metadata.json', {
            'label': label, 'mode': 'fixed' if label == 'backend-fixed' else 'off',
            'scenario': 'mixed', 'seed': 42, 'seconds': 30, 'report_rounds': 40,
            'fixed_limit': fixed_limit, 'backend': 'postgresql', 'workers': 4,
            'source_sha256': {'server.py': source},
            'schedule_sha256': hashlib.sha256((data_dir / 'schedule.json').read_bytes()).hexdigest()})
        if cancellation:
            write_json(data_dir / 'summary.json', {'experiment_type': 'cancellation_probe', 'observation': 'inconclusive'})
        for variant in ('wait', 'cancel') if cancellation else ('',):
            run_dir = data_dir / variant if variant else data_dir
            summary = {'all': group(), 'normal_orders_load_phase': group(),
                       'normal_reports_load_phase': group(successes=report_successes, rejected=10-report_successes),
                       'order_audit_ok': True, 'deadline_ms': 1000}
            if cancellation:
                summary.update(experiment_type='cancellation_probe', variant=variant)
            write_json(run_dir / ('metrics.json' if cancellation else 'summary.json'), summary)
            write_json(run_dir / 'order_audit.json', {
                'detailed_audit_available': not old, 'order_details_match_ids': True,
                'per_product_stock_matches_orders': True, 'stock_matches_orders': True})
            if not old:
                write_json(run_dir / 'final_state.json', {'run_id': f'{label}-{variant}'})
                write_json(run_dir / 'events.json', {'run_id': f'{label}-{variant}', 'events': []})
                write_json(run_dir / 'evidence.json', {
                    'schema_version': 1, 'run_id': f'{label}-{variant}', 'status': 'complete',
                    'observations': {'order_report_overlap_ms': overlapping, 'peak_running': 2,
                                     'queue': {'p95_ms': 1}, 'residual_after_disconnect': {'total_ms': 0}},
                    'coverage': {'event_count': 20, 'dropped_events': 0}, 'limitations': []})
        return variant_dir, data_dir

    def test_legacy_data_is_displayed_with_evidence_limits(self):
        self.make_run('gateway-off', old=True)
        runs = load_runs(self.root)
        self.assertEqual(len(runs), 1)
        flags = ' '.join(evidence_flags(runs[0]))
        self.assertIn('基準未出現訂單SLO損害', flags)
        self.assertIn('缺少 evidence.json', flags)
        self.assertIn('host_resources', flags)
        rendered = render_report(runs, self.root / 'report.html')
        self.assertIn('舊格式：僅 ID／總庫存', rendered)
        self.assertIn('summary.json', rendered)

    def test_state_transitions_without_rate_changes_do_not_verify_feedback(self):
        variant_dir, _ = self.make_run('adaptive-rls-feedback', feedback=True)
        write_json(variant_dir / 'rls_logs_after.json', {'events': [
            {'event': 'run_reset', 'run_id': 'adaptive-rls-feedback-', 'report_rate': 2},
            {'event': 'control_update', 'run_id': 'adaptive-rls-feedback-',
             'state': 'recovering', 'previous_report_rate': 2, 'report_rate': 2}]})
        run = load_runs(self.root)[0]
        self.assertEqual(run['feedback']['changes'], 0)
        self.assertIn('未驗證動態控制', ' '.join(evidence_flags(run)))

    def test_missing_feedback_log_is_unknown_not_zero(self):
        self.make_run('adaptive-rls-feedback', feedback=True)
        run = load_runs(self.root)[0]
        self.assertIsNone(run['feedback']['changes'])
        self.assertIn('不視為 0 次調速', ' '.join(evidence_flags(run)))

    def test_missing_raw_events_is_an_observation_limit_even_with_derived_evidence(self):
        _, data_dir = self.make_run('gateway-off', overlapping=20)
        (data_dir / 'events.json').unlink()
        run = load_runs(self.root)[0]
        self.assertIn('缺少原始 events.json', ' '.join(evidence_flags(run)))

    def test_cancellation_rounds_load_parent_files_and_filter_logs(self):
        variant_dir, _ = self.make_run('adaptive-rls-feedback', cancellation=True, feedback=True)
        write_json(variant_dir / 'rls_logs_after.json', {'events': [
            {'event': 'control_update', 'run_id': 'adaptive-rls-feedback-wait', 'previous_report_rate': 2, 'report_rate': 2},
            {'event': 'control_update', 'run_id': 'adaptive-rls-feedback-cancel', 'previous_report_rate': 2, 'report_rate': 1}]})
        runs = {run['variant']: run for run in load_runs(self.root)}
        self.assertEqual(set(runs), {'wait', 'cancel'})
        self.assertEqual(runs['wait']['feedback']['changes'], 0)
        self.assertEqual(runs['cancel']['feedback']['changes'], 1)
        self.assertTrue(runs['wait']['schedule_hash_ok'])
        self.assertNotEqual(runs['wait']['condition_id'], runs['cancel']['condition_id'])
        rendered = render_report(list(runs.values()), self.root / 'report.html')
        self.assertIn('metrics.json', rendered)
        self.assertIn('run/metadata.json', rendered)
        self.assertIn('run/schedule.json', rendered)

    def test_fixed_limit_is_policy_not_load_and_report_tradeoff_is_shown(self):
        self.make_run('gateway-off', fixed_limit=2)
        self.make_run('backend-fixed', fixed_limit=1, report_successes=6)
        pairs = paired_differences(load_runs(self.root))
        self.assertEqual(len(pairs), 1)
        self.assertIsNotNone(pairs[0]['baseline'])
        self.assertEqual(pairs[0]['orders_pp'], 0)
        self.assertEqual(pairs[0]['reports_pp'], -40)
        self.assertEqual(pairs[0]['report_rejections'], 4)

    def test_incompatible_sources_resources_schedule_and_repeats_do_not_pair(self):
        cases = ({'source': 'source-b'}, {'host_cpus': 4}, {'schedule_offset': 2}, {'repeat_index': 1})
        for changes in cases:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as directory:
                previous = self.root
                self.root = Path(directory)
                self.make_run('gateway-off')
                self.make_run('backend-fixed', **changes)
                self.assertIsNone(paired_differences(load_runs(self.root))[0]['baseline'])
                self.root = previous

    def test_cancellation_wait_and_cancel_pair_separately(self):
        self.make_run('gateway-off', cancellation=True)
        self.make_run('backend-fixed', cancellation=True)
        pairs = paired_differences(load_runs(self.root))
        self.assertEqual(len(pairs), 2)
        for pair in pairs:
            self.assertIsNotNone(pair['baseline'])
            self.assertEqual(pair['run']['variant'], pair['baseline']['variant'])

    def test_zero_overlap_incomplete_events_and_html_are_not_overclaimed(self):
        _, data_dir = self.make_run('<script>alert(1)</script>', overlapping=0)
        evidence = json.loads((data_dir / 'evidence.json').read_text())
        evidence.update(status='incomplete', validity_issues=['<img src=x onerror=alert(1)>'])
        write_json(data_dir / 'evidence.json', evidence)
        rendered = render_report(load_runs(self.root), self.root / 'report.html')
        self.assertIn('未觀察到訂單與報表工作重疊', rendered)
        self.assertIn('事件證據不完整', rendered)
        self.assertIn('不能直接稱為壅塞', rendered)
        self.assertNotIn('<script>', rendered)
        self.assertNotIn('<img src=x', rendered)
        self.assertIn('&lt;script&gt;', rendered)


if __name__ == '__main__':
    unittest.main()
