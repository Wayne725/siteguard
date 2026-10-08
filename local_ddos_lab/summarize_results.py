"""Build an offline, evidence-aware comparison without choosing a winning policy."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


def optional_json(path: Path) -> dict:
    return read_json(path) if path.is_file() else {}


def escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def manifest_context(path: Path, boundary: Path) -> tuple[Path | None, dict, str]:
    variant_path, variant, batch = None, {}, ''
    for parent in (path, *path.parents):
        manifest_path = parent / 'manifest.json'
        value = optional_json(manifest_path)
        if not variant and value.get('label'):
            variant_path, variant = manifest_path, value
        if value.get('variants'):
            batch = str(manifest_path.resolve())
        if parent == boundary or parent.parent == parent:
            break
    if not batch and variant_path:
        batch = str(variant_path.parent.parent.resolve())
    return variant_path, variant, batch


def load_runs(directory: Path) -> list[dict]:
    directory = directory.resolve()
    paths = list(directory.rglob('summary.json')) + list(directory.rglob('metrics.json'))
    runs = []
    for path in sorted(paths):
        summary = read_json(path)
        cancellation = summary.get('experiment_type') == 'cancellation_probe'
        if 'all' not in summary or (cancellation and path.name != 'metrics.json'):
            continue
        data_dir = path.parent.parent if cancellation else path.parent
        metadata = optional_json(data_dir / 'metadata.json')
        if not metadata:
            continue
        manifest_path, manifest, batch = manifest_context(path.parent, directory)
        schedule_path = data_dir / 'schedule.json'
        schedule_hash = hashlib.sha256(schedule_path.read_bytes()).hexdigest() if schedule_path.is_file() else None
        evidence = optional_json(path.parent / 'evidence.json')
        final_state = optional_json(path.parent / 'final_state.json')
        variant = summary.get('variant', '') if cancellation else ''
        conditions = {key: metadata.get(key) for key in (
            'scenario', 'seed', 'seconds', 'arrival', 'arrival_window_s', 'report_rounds', 'rows', 'backend', 'reset_settle_s',
            'workers', 'max_outstanding', 'queue_timeout_s', 'sql_execution_timeout_s',
            'client_max_inflight', 'client_timeout_s', 'sqlite', 'versions',
            'kind', 'cancel_after_ms', 'probe_rate_per_s', 'normal_order_rate_per_s', 'max_inflight',
            'round_order', 'gateway_state_shared_between_rounds', 'warmup_requests')}
        conditions.update(experiment_type='cancellation_probe' if cancellation else 'regular',
                          cancellation_variant=variant, schedule_sha256=schedule_hash,
                          deadline_ms=summary.get('deadline_ms'), source_sha256=metadata.get('source_sha256'),
                          comparison_source_sha256=manifest.get('source_sha256'),
                          containers=manifest.get('containers'), host_resources=manifest.get('host_resources'),
                          envoy_version=manifest.get('envoy_version'))
        missing = [key for key in ('schedule_sha256', 'source_sha256', 'comparison_source_sha256',
                                   'containers', 'host_resources') if not conditions.get(key)]
        hash_ok = bool(schedule_hash) and metadata.get('schedule_sha256', schedule_hash) == schedule_hash
        if not hash_ok:
            missing.append('schedule_hash_mismatch')
        if manifest and manifest.get('status') != 'complete':
            missing.append('manifest_not_complete')
        groups = summary.get('by_label_phase_kind', {})
        run = {'path': path.parent, 'summary_path': path, 'data_dir': data_dir,
               'summary': summary, 'metadata': metadata, 'manifest_path': manifest_path,
               'manifest': manifest, 'batch': batch, 'variant': variant,
               'run_id': evidence.get('run_id') or final_state.get('run_id'),
               'audit': optional_json(path.parent / 'order_audit.json'), 'evidence': evidence,
               'condition_id': hashlib.sha256(json.dumps(conditions, sort_keys=True).encode()).hexdigest()[:12],
               'conditions': conditions, 'pairing_missing': missing, 'schedule_hash_ok': hash_ok,
               'repeat_index': manifest.get('repeat_index', 0),
               'reports': summary.get('normal_reports_load_phase', groups.get('normal/load/report', {}))}
        run['feedback'] = feedback_observation(run)
        runs.append(run)
    return sorted(runs, key=lambda run: (str(run['metadata'].get('scenario', 'cancellation')),
                                        str(run['metadata'].get('seed', '')),
                                        str(run['repeat_index']), str(run['path'])))


def feedback_observation(run: dict) -> dict:
    if run['manifest'].get('rls_mode') != 'feedback' and 'feedback' not in run['metadata'].get('label', ''):
        return {'applicable': False, 'changes': None, 'events': []}
    def unknown(reason):
        return {'applicable': True, 'changes': None, 'events': [], 'reason': reason}
    manifest_path = run['manifest_path']
    log_path = manifest_path.parent / 'rls_logs_after.json' if manifest_path else None
    if not log_path or not log_path.is_file():
        return unknown('缺少 RLS 日誌')
    logs = read_json(log_path)
    events = logs.get('events', [])
    run_id = run['run_id']
    run_ids = {event['run_id'] for event in events if event.get('run_id')}
    if not run_id and len(run_ids) == 1 and not run['variant']:
        run_id = next(iter(run_ids))
    if not run_id:
        return unknown('無法對應 round run_id')
    selected = [event for event in events if event.get('run_id') == run_id]
    if not selected:
        return unknown('日誌缺少此 round')
    updates = [event for event in selected if event.get('event') == 'control_update']
    if any('report_rate' not in event or 'previous_report_rate' not in event for event in updates):
        return unknown('調速欄位不完整')
    return {'applicable': True, 'changes': sum(event['report_rate'] != event['previous_report_rate'] for event in updates),
            'events': selected, 'omitted_lines': logs.get('unstructured_lines_omitted', 0)}


def run_label(run: dict) -> str:
    label = run['manifest'].get('label') or run['metadata'].get('label') or run['metadata'].get('mode', '')
    return f'{label} / {run["variant"]}' if run['variant'] else label


def is_baseline(run: dict) -> bool:
    return (run['manifest'].get('label') or run['metadata'].get('label')) == 'gateway-off'


def evidence_flags(run: dict) -> list[str]:
    flags = []
    if run['variant'] and run['metadata'].get('base_url', '').endswith(':8080'):
        if run['metadata'].get('gateway_state_shared_between_rounds'):
            flags.append('wait/cancel 共用 Envoy 控制器狀態；暖機差異仍可能影響結果，不能直接推定取消的因果效果')
        elif 'gateway_state_shared_between_rounds' not in run['metadata']:
            flags.append('觀測限制：缺少取消兩輪的閘道初始化條件')
    orders = run['summary'].get('normal_orders_load_phase', {})
    if is_baseline(run) and orders.get('planned', 0) > 0 and orders.get('success_within_deadline') == orders['planned']:
        flags.append('基準未出現訂單SLO損害')
    feedback = run['feedback']
    if feedback['applicable']:
        if feedback['changes'] is None:
            flags.append(f'動態控制證據未知：{feedback["reason"]}（不視為 0 次調速）')
        elif feedback['changes'] == 0:
            flags.append('未驗證動態控制：日誌沒有實際 report_rate 變更')
        else:
            flags.append(f'觀察到 {feedback["changes"]} 次調速；不代表訂單因此改善')
        if feedback.get('omitted_lines'):
            flags.append('RLS 日誌含未結構化省略行，控制軌跡可能不完整')
    evidence = run['evidence']
    if not evidence:
        flags.append('觀測限制：缺少 evidence.json，未證明工作重疊或壅塞')
    else:
        if not (run['path'] / 'events.json').is_file():
            flags.append('觀測限制：缺少原始 events.json，無法覆核事件證據')
        if evidence.get('status') != 'complete':
            flags.append('觀測限制：事件證據不完整')
        overlap = evidence.get('observations', {}).get('order_report_overlap_ms')
        if overlap is None:
            flags.append('觀測限制：缺少訂單／報表重疊量測')
        elif overlap == 0:
            flags.append('觀測限制：未觀察到訂單與報表工作重疊；不能據此驗證競爭防護')
        flags.extend(str(value) for value in evidence.get('validity_issues', []))
    if run['pairing_missing']:
        flags.append('不作自動配對：缺少或不符 ' + ', '.join(run['pairing_missing']))
    if run['summary']['all'].get('generator_drops', 0):
        flags.append('產生器漏送不為零：實際送入負載不等於原定負載')
    return flags


def rate(group: dict, field: str) -> float | None:
    return group.get(field, 0) / group['planned'] if group.get('planned', 0) else None


def paired_differences(runs: list[dict]) -> list[dict]:
    pairs = []
    for run in runs:
        if is_baseline(run):
            continue
        candidates = [baseline for baseline in runs if is_baseline(baseline)
                      and not baseline['pairing_missing'] and not run['pairing_missing']
                      and baseline['condition_id'] == run['condition_id']
                      and baseline['repeat_index'] == run['repeat_index'] and baseline['batch'] == run['batch']]
        if len(candidates) != 1:
            pairs.append({'run': run, 'baseline': None,
                          'reason': '無相容基準或證據不足' if not candidates else '多個相容基準，配對不唯一'})
            continue
        baseline, differences = candidates[0], {}
        for key, field in (('orders_pp', 'success_within_deadline'), ('reports_pp', 'business_successes')):
            left = rate(run['reports'] if key == 'reports_pp' else run['summary'].get('normal_orders_load_phase', {}), field)
            right = rate(baseline['reports'] if key == 'reports_pp' else baseline['summary'].get('normal_orders_load_phase', {}), field)
            differences[key] = (left - right) * 100 if left is not None and right is not None else None
        differences['report_rejections'] = run['reports'].get('http_429', 0) - baseline['reports'].get('http_429', 0)
        differences['drops'] = run['summary']['all'].get('generator_drops', 0) - baseline['summary']['all'].get('generator_drops', 0)
        pairs.append({'run': run, 'baseline': baseline, **differences})
    return pairs


def completion_cell(group: dict, numerator: str) -> str:
    count, planned = group.get(numerator, 0), group.get('planned', 0)
    if not planned:
        return '<span class="muted">— / 0（無樣本）</span>'
    percent = count / planned * 100
    return (f'<strong>{escape(count)} / {escape(planned)}</strong> · {percent:.1f}%'
            f'<div class="bar"><span style="width:{max(0, min(percent, 100)):.2f}%"></span></div>')


def audit_result(run: dict) -> tuple[str, str]:
    audit = run['audit']
    if not audit:
        return 'bad', '缺少稽核'
    if not run['summary'].get('order_audit_ok'):
        return 'bad', '未通過'
    if not audit.get('detailed_audit_available'):
        return 'warn', '舊格式：僅 ID／總庫存'
    if not all(audit.get(key) for key in ('order_details_match_ids', 'per_product_stock_matches_orders', 'stock_matches_orders')):
        return 'bad', '逐商品核對未通過'
    return 'good', 'ID／商品／庫存通過'


def raw_links(run: dict, output: Path) -> str:
    folders = {run['path'], run['data_dir']}
    if run['manifest_path']:
        folders.add(run['manifest_path'].parent)
    files = {path for folder in folders for path in folder.iterdir() if path.is_file()}
    batch_path = Path(run['batch']) if run['batch'] else None
    if batch_path and batch_path.is_file():
        files.add(batch_path)
    links = []
    for path in sorted(files):
        if path.resolve() == output.resolve():
            continue
        relative = quote(os.path.relpath(path, output.parent), safe='/')
        label = path.name if path.parent == run['path'] else f'{path.parent.name}/{path.name}'
        links.append(f'<a href="{escape(relative)}">{escape(label)}</a>')
    return ' · '.join(links)


def number(value: object) -> str:
    return '未知' if value is None else escape(round(value, 3) if isinstance(value, float) else value)


def observation_html(run: dict) -> str:
    evidence = run['evidence']
    if not evidence:
        return '<p class="warn">缺少事件證據；舊紀錄仍保留，但不反推未量測的工作重疊。</p>'
    values, coverage = evidence.get('observations', {}), evidence.get('coverage', {})
    queue, residual = values.get('queue', {}), values.get('residual_after_disconnect', {})
    return f'''<p>事件完整性：{escape(evidence.get('status', '未知'))}；事件 {number(coverage.get('event_count'))} 筆，遺失 {number(coverage.get('dropped_events'))} 筆。</p>
<p>訂單／報表重疊 {number(values.get('order_report_overlap_ms'))} ms；最高執行中 {number(values.get('peak_running'))}；worker 容量 {number(values.get('worker_capacity'))}；達容量時間 {number(values.get('worker_capacity_reached_ms'))} ms。</p>
<p>排隊 p95／最大：{number(queue.get('p95_ms'))} / {number(queue.get('max_ms'))} ms（{number(queue.get('measured_requests'))} 筆）；斷線後殘留總計／最大：{number(residual.get('total_ms'))} / {number(residual.get('max_ms'))} ms（{number(residual.get('completed_requests'))} 筆）。</p>
<p class="muted">重疊與 worker 達容量只是工作並存觀測；需同時看排隊、期限與拒絕，不能直接稱為壅塞。斷線後清理時間從伺服器觀察斷線起算，不等於完整取消成本或 DB CPU 時間；完整限制保留於下方原始證據。</p>
<pre>{escape(json.dumps(evidence, ensure_ascii=False, indent=2))}</pre>'''


def delta(value: float | int | None, suffix: str = '') -> str:
    return '無樣本' if value is None else f'{value:+.1f}{suffix}'


def render_report(runs: list[dict], output: Path) -> str:
    table_rows, details, pair_rows = [], [], []
    indexes = {str(run['path']): index for index, run in enumerate(runs, 1)}
    for index, run in enumerate(runs, 1):
        summary, metadata = run['summary'], run['metadata']
        total, orders = summary['all'], summary.get('normal_orders_load_phase', {})
        audit_class, audit_label = audit_result(run)
        dropped, label = total.get('generator_drops', 0), run_label(run)
        flags = evidence_flags(run)
        table_rows.append(f'''<tr>
<td>{escape(metadata.get('scenario', '取消觀測'))}<br><span class="muted">seed {escape(metadata.get('seed', '未知'))} · repeat {escape(run['repeat_index'])}</span></td>
<td><a href="#run-{index}">{escape(label)}</a><br><span class="muted">{escape(metadata.get('mode', ''))} · {escape(metadata.get('transport_path', metadata.get('base_url', 'origin')))}</span></td>
<td>{escape(total.get('planned', 0))}<br><span class="muted">送出 {escape(total.get('issued', 0))}</span></td>
<td>{completion_cell(orders, 'success_within_deadline')}</td><td>{completion_cell(run['reports'], 'business_successes')}<br><span class="muted">正常報表 429：{escape(run['reports'].get('http_429', 0))}</span></td>
<td class="{'bad' if dropped else ''}">{escape(dropped)}</td><td>{escape(total.get('client_timeouts', 0))}</td>
<td>{escape(total.get('http_429', 0))} / {escape(total.get('http_5xx', 0))}</td><td class="{audit_class}">{audit_label}</td>
<td class="evidence">{'<br>'.join(escape(flag) for flag in flags) or '保留觀測，未推定因果'}</td></tr>''')
        late_commits = len(run['audit'].get('committed_without_successful_ack', []))
        trajectory = ('<p>此 round 的 RLS 事件：</p><pre>' + escape(json.dumps(run['feedback']['events'], ensure_ascii=False, indent=2)) + '</pre>') if run['feedback']['events'] else ''
        details.append(f'''<details id="run-{index}"><summary>{index}. {escape(label)} · {escape(run['path'].name)}</summary>
<p>{raw_links(run, output)}</p><p>條件組：<code>{escape(run['condition_id'])}</code>；期限 {escape(summary.get('deadline_ms'))} ms；報表 SQL 輪數 {escape(metadata.get('report_rounds'))}；執行 {escape(metadata.get('seconds'))} 秒。</p>
<p>有提交但未收到有效成功回應：{late_commits} 筆，不計入準時成功。</p>{observation_html(run)}{trajectory}
<p>參數：</p><pre>{escape(json.dumps(metadata, ensure_ascii=False, indent=2))}</pre></details>''')
    for pair in paired_differences(runs):
        run = pair['run']
        target = f'<a href="#run-{indexes[str(run["path"])]}">{escape(run_label(run))}</a>'
        if not pair['baseline']:
            pair_rows.append(f'<tr><td>{target}</td><td colspan="6">{escape(pair["reason"])}</td></tr>')
            continue
        baseline, caveats = pair['baseline'], []
        if '基準未出現訂單SLO損害' in evidence_flags(baseline):
            caveats.append('基準未出現訂單SLO損害')
        if any(item['summary']['all'].get('generator_drops', 0) for item in (run, baseline)):
            caveats.append('有 drops，僅描述差異')
        if any(audit_result(item)[0] != 'good' for item in (run, baseline)):
            caveats.append('audit 證據不足')
        if any(not item['evidence'] or item['evidence'].get('status') != 'complete'
               or not (item['path'] / 'events.json').is_file()
               or not item['evidence'].get('observations', {}).get('order_report_overlap_ms')
               for item in (run, baseline)):
            caveats.append('事件觀測不足，不能歸因於資源競爭')
        caveats.append('單輪配對差異，不推定演算法優勢')
        pair_rows.append(f'''<tr><td>{target}<br><span class="muted">repeat {escape(run['repeat_index'])} / seed {escape(run['metadata'].get('seed'))}</span></td>
<td><a href="#run-{indexes[str(baseline['path'])]}">{escape(run_label(baseline))}</a></td><td>{delta(pair['orders_pp'], ' pp')}</td><td>{delta(pair['reports_pp'], ' pp')}</td>
<td>{delta(pair['report_rejections'])}</td><td>{delta(pair['drops'])}</td><td class="evidence">{'；'.join(caveats)}</td></tr>''')
    return f'''<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>本機資源防護實驗比較</title><style>
:root{{font-family:-apple-system,BlinkMacSystemFont,"Noto Sans TC",sans-serif;color:#172c37;background:#f5f7f8}}
body{{max-width:1600px;margin:0 auto;padding:36px 24px}}h1{{font-size:28px;margin-bottom:8px}}p,li{{line-height:1.7}}
.muted{{color:#62717a;font-size:13px}}.notice{{padding:16px 20px;background:#e6edf0;border-left:4px solid #416479}}
.scroll{{overflow-x:auto;background:white;margin:24px 0}}table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{padding:14px 12px;border-bottom:1px solid #dce4e8;text-align:left;vertical-align:top;white-space:nowrap}}
th{{background:#233f50;color:white;font-size:13px}}a{{color:#175c80}}.good{{color:#136b54}}.warn{{color:#865805}}.bad{{color:#a72428}}
.evidence{{white-space:normal;min-width:260px;line-height:1.7}}.bar{{height:5px;background:#e7edf0;margin-top:8px;max-width:180px}}.bar span{{display:block;height:5px;background:#24826d}}
details{{background:white;margin:10px 0;padding:16px}}summary{{cursor:pointer;font-weight:600}}pre{{overflow:auto;font-size:12px;max-height:360px}}
code{{font-size:12px}}footer{{margin-top:28px;color:#62717a}}
</style></head><body><h1>本機資源防護實驗比較</h1><p>{len(runs)} 次執行 · 離線報告，無外部腳本或連線</p>
<div class="notice">正常訂單主指標＝負載階段內「期限內收到成功回應且通過訂單核對」的正常訂單 ÷ 該階段預定正常訂單。正常報表完成率不套用訂單期限；拒絕與漏送保留在分母。</div>
<ul><li>配對需同一 batch／repeat、相同種子與時程、來源 hash、資料庫與負載參數、容器與主機資源。防護模式及 fixed_limit 是比較變因。缺證據不自動視為相同。</li>
<li>取消觀測的 wait／cancel 各自比較，不互相混配；日誌依 round run_id 對應。缺日誌不代表零次調速。</li>
<li>基準全準時代表未觀察到訂單 SLO 損害；工作重疊、worker 達容量與控制器有動作，都不單獨證明壅塞或保護效果。</li>
<li>舊格式稽核、事件遺失與產生器 drops 會限制結論。配對表只列差異，不自動挑選勝出方法。</li></ul>
<div class="scroll"><table><thead><tr><th>情境</th><th>組別／入口</th><th>全部 planned</th><th>正常訂單準時完成</th><th>正常報表完成／拒絕</th><th>drops</th><th>client timeouts</th><th>全部 429 / 5xx</th><th>audit</th><th>證據與限制</th></tr></thead><tbody>{''.join(table_rows)}</tbody></table></div>
<h2>每輪相對 gateway-off 的差異</h2><p>pp＝百分點；正值表示相對基準增加。報表完成與拒絕一併展示服務取捨。</p>
<div class="scroll"><table><thead><tr><th>組別</th><th>基準</th><th>訂單準時率差</th><th>報表完成率差</th><th>正常報表 429 差</th><th>drops 差</th><th>解讀限制</th></tr></thead><tbody>{''.join(pair_rows) or '<tr><td colspan="7">沒有可比較的非基準組別</td></tr>'}</tbody></table></div>
<h2>參數、事件與原始紀錄</h2>{''.join(details)}<footer>僅供隔離、本機應用層資源競爭實驗。未量測的證據保持未知，不由成功率反推。</footer></body></html>'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results_dir', type=Path, nargs='?', default=ROOT / 'results')
    parser.add_argument('--output', type=Path, default=ROOT / 'results' / 'comparison.html')
    args = parser.parse_args()
    if not args.results_dir.is_dir():
        parser.error(f'Results directory does not exist: {args.results_dir}')
    runs = load_runs(args.results_dir)
    if not runs:
        parser.error(f'No supported summary.json or cancellation metrics.json found in {args.results_dir}')
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_report(runs, output), encoding='utf-8')
    print(f'{len(runs)} runs → {output}')


if __name__ == '__main__':
    main()
