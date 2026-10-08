import unittest

from event_analysis import analyze_events


def request(request_id, kind, **values):
    return dict(request_id=request_id, kind=kind, issued=True, business_ok=True) | values


def lifecycle(request_id, kind, start, end, disconnected=None, queue_ms=0):
    events = [dict(request_id=request_id, kind=kind, event='accepted',
                   elapsed_s=start - queue_ms / 1000),
              dict(request_id=request_id, kind=kind, event='db_work_started', elapsed_s=start,
                   queue_ms=queue_ms),
              dict(request_id=request_id, kind=kind, event='db_work_finished', elapsed_s=end)]
    if disconnected is not None:
        events.append(dict(request_id=request_id, kind=kind, event='http_disconnect_observed',
                           elapsed_s=disconnected))
    return events


def evidence(rows, events, **envelope):
    return analyze_events(rows, dict(run_id='one', events=events, capacity=4096) | envelope,
                          {'run_id': 'one', 'db_workers': 4, 'running': {}, 'outstanding': {}}, 'one')


class EventEvidenceTests(unittest.TestCase):
    def test_overlap_is_wall_clock_union_and_not_saturation(self):
        rows = [request('report1', 'report'), request('report2', 'report'), request('order', 'orders')]
        events = (lifecycle('report1', 'report', 1, 3)
                  + lifecycle('report2', 'report', 1.5, 2.5)
                  + lifecycle('order', 'orders', 2, 4, queue_ms=20))
        result = evidence(rows, events)
        observed = result['observations']
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(observed['order_report_overlap_ms'], 1000)
        self.assertEqual(observed['order_report_overlap_pairs'], 2)
        self.assertEqual(observed['orders_overlapping_reports'], 1)
        self.assertEqual(observed['peak_running'], 3)
        self.assertFalse(observed['worker_capacity_reached'])
        self.assertEqual(observed['queue']['by_kind']['orders']['p95_ms'], 20)
        self.assertIn('do not establish saturation', result['limitations'][0])

    def test_capacity_duration_and_residual_are_integrated(self):
        rows = [request(str(index), 'report') for index in range(4)]
        events = [event for index in range(4)
                  for event in lifecycle(str(index), 'report', 1, 2, disconnected=1.75)]
        observed = evidence(rows, events)['observations']
        self.assertEqual(observed['worker_capacity_reached_ms'], 1000)
        self.assertEqual(observed['residual_after_disconnect']['total_ms'], 1000)
        self.assertEqual(observed['residual_after_disconnect']['max_ms'], 250)
        self.assertEqual(observed['residual_after_disconnect']['completed_requests'], 4)

    def test_nonoverlapping_or_touching_intervals_are_not_overlap(self):
        rows = [request('report', 'report'), request('order', 'orders')]
        result = evidence(rows, lifecycle('report', 'report', 1, 2) + lifecycle('order', 'orders', 2, 3))
        self.assertEqual(result['observations']['order_report_overlap_ms'], 0)
        self.assertEqual(result['observations']['peak_running'], 1)

    def test_rejections_and_queue_cancellation_have_complete_lifecycles(self):
        rows = [request('reject', 'report', business_ok=False),
                request('queue', 'orders', business_ok=False),
                request('proxy', 'report', business_ok=False)]
        events = [dict(request_id='reject', kind='report', event='admission_rejected', elapsed_s=1),
                  dict(request_id='queue', kind='orders', event='accepted', elapsed_s=1),
                  dict(request_id='queue', kind='orders', event='http_disconnect_observed', elapsed_s=1.1),
                  dict(request_id='queue', kind='orders', event='queue_exit', elapsed_s=1.2)]
        result = evidence(rows, events)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['coverage']['missing_origin_request_ids'], ['proxy'])
        self.assertEqual(result['observations']['peak_running'], 0)

    def test_incomplete_duplicate_mismatched_and_foreign_lifecycles_fail(self):
        valid = lifecycle('one', 'report', 1, 2)
        cases = [valid[:-1], valid + [valid[0]], lifecycle('one', 'orders', 1, 2),
                 valid + lifecycle('foreign', 'orders', 1, 2), [],
                 lifecycle('one', 'report', 2, 1)]
        for events in cases:
            with self.subTest(events=events):
                self.assertEqual(evidence([request('one', 'report')], events)['status'], 'incomplete')

    def test_exact_truncation_and_legacy_full_buffer_are_not_valid_evidence(self):
        rows, events = [request('one', 'report')], lifecycle('one', 'report', 1, 2)
        self.assertEqual(evidence(rows, events, total_events=4, dropped_events=1)['status'], 'incomplete')
        self.assertEqual(evidence(rows, events, capacity=3)['status'], 'incomplete')
        self.assertEqual(evidence(rows, events, capacity=3, total_events=3,
                                  dropped_events=0)['status'], 'complete')


if __name__ == '__main__':
    unittest.main(verbosity=2)
