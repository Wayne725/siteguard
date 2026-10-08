import contextlib
import io
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

from siteguard import cli, deployment
from siteguard.config import validate_config


def config_fixture():
    return validate_config({'version': 1, 'name': 'siteguard', 'mode': 'observe',
                            'listener': {'host': '127.0.0.1', 'port': 8088},
                            'upstream': {'url': 'http://host.docker.internal:8000'}})


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'deployment with spaces'
        self.config_path = self.root / 'siteguard.yaml'
        self.config = config_fixture()
        self.renderer = patch.object(deployment, 'render_envoy', return_value={
            'admin': {'address': {'socket_address': {'address': '127.0.0.1', 'port_value': 9901}}},
            'static_resources': {}})
        self.renderer.start()
        self.addCleanup(self.renderer.stop)
        policy_renderer = patch.object(deployment, 'render_policy', return_value={'mode': 'observe'})
        policy_renderer.start()
        self.addCleanup(policy_renderer.stop)
        policy_source = patch.object(deployment, 'policy_source', return_value='print("policy")\n')
        policy_source.start()
        self.addCleanup(policy_source.stop)

    def invoke(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_common_options_work_before_and_after_subcommand(self):
        for argv in (['--config', str(self.config_path), 'check'],
                     ['check', '--config', str(self.config_path)]):
            with patch.object(cli, 'load_config', return_value=self.config) as load:
                code, _, error = self.invoke(argv)
                self.assertEqual((code, error), (0, ''))
                load.assert_called_once_with(self.config_path)

    def test_check_and_render_never_invoke_docker(self):
        with patch.object(cli, 'load_config', return_value=self.config):
            with patch.object(deployment.subprocess, 'run') as run:
                code, output, _ = self.invoke(['check'])
                self.assertEqual(code, 0)
                self.assertIn('尚未執行 Envoy 原生驗證', output)
                code, _, _ = self.invoke(['render', '--output', str(self.output)])
                self.assertEqual(code, 0)
                self.assertTrue((self.output / 'envoy.yaml').is_file())
                self.assertTrue((self.output / 'compose.yaml').is_file())
                run.assert_not_called()

    def test_check_reports_observe_guards_as_inactive_without_exposing_rule_details(self):
        raw = config_fixture()
        raw['upstream']['url'] = 'https://private-origin.example'
        raw['security']['protected_paths'] = [
            {'prefix': '/private-operator-console', 'allowed_cidrs': ['203.0.113.19/32']},
        ]
        raw['routes'] = [
            {'name': 'account_private', 'prefix': '/private-account-api',
             'response_guard': True, 'max_body_bytes': 4096},
            {'name': 'ordinary', 'prefix': '/ordinary'},
        ]
        self.config_path.write_text(yaml.safe_dump(raw))
        with patch.object(deployment.subprocess, 'run') as run:
            code, output, error = self.invoke(['check', '--config', str(self.config_path)])
        self.assertEqual((code, error), (0, ''))
        for text in ('模式：observe', '敏感檔案路徑封鎖：設定開啟', '封鎖 methods：3 種',
                     'protected_paths：1 條', '回應安全標頭：設定開啟',
                     'response_guard：設定 1 條／依此模式實際啟用 0 條',
                     '只記錄資安請求影子規則', '不掃描回應內容', '非目前部署狀態'):
            self.assertIn(text, output)
        for private in ('private-origin.example', '/private-operator-console', '203.0.113.19',
                        '/private-account-api', 'account_private', '4096'):
            self.assertNotIn(private, output)
        run.assert_not_called()

    def test_check_reports_enforce_guard_count_and_disabled_controls(self):
        raw = config_fixture()
        raw['mode'] = 'enforce'
        raw['security'] = {'block_sensitive_paths': False, 'response_headers': False,
                           'blocked_methods': [], 'protected_paths': []}
        raw['routes'] = [
            {'name': 'api_one', 'prefix': '/api/one', 'response_guard': True, 'max_body_bytes': 4096},
            {'name': 'api_two', 'prefix': '/api/two', 'response_guard': True, 'max_body_bytes': 2048},
            {'name': 'events', 'prefix': '/events', 'streaming': True},
        ]
        self.config_path.write_text(yaml.safe_dump(raw))
        code, output, error = self.invoke(['check', '--config', str(self.config_path)])
        self.assertEqual((code, error), (0, ''))
        for text in ('模式：enforce', '敏感檔案路徑封鎖：設定關閉', '封鎖 methods：0 種',
                     'protected_paths：0 條', '回應安全標頭：設定關閉',
                     'response_guard：設定 2 條／依此模式實際啟用 2 條',
                     '並非完整資料外洩防護', '尚未執行 Envoy 原生驗證'):
            self.assertIn(text, output)
        self.assertNotIn('不掃描回應內容', output)

    def test_init_preserves_existing_file_unless_force_is_explicit(self):
        with patch.object(cli, 'example_config', return_value=self.config):
            args = ['init', '--config', str(self.config_path)]
            self.assertEqual(self.invoke(args)[0], 0)
            self.config_path.write_text('existing: keep\n')
            self.assertEqual(self.invoke(args)[0], 1)
            self.assertEqual(self.config_path.read_text(), 'existing: keep\n')
            self.assertEqual(self.invoke(args + ['--force'])[0], 0)
            self.assertEqual(yaml.safe_load(self.config_path.read_text())['name'], 'siteguard')

    def test_firewall_summary_reports_priority_and_mode_without_private_cidrs(self):
        raw = config_fixture()
        raw['firewall'] = {'default_action': 'deny', 'allow_cidrs': ['203.0.113.0/24'],
                           'deny_cidrs': ['203.0.113.18']}
        for mode in ('observe', 'enforce'):
            raw['mode'] = mode
            self.config_path.write_text(yaml.safe_dump(raw))
            code, output, error = self.invoke(['check', '--config', str(self.config_path)])
            self.assertEqual((code, error), (0, ''))
            self.assertIn('預設 deny；允許 1 個網段／封鎖 1 個網段；封鎖優先', output)
            self.assertNotIn('203.0.113', output)
            self.assertEqual('不封鎖' in output, mode == 'observe')

    def test_firewall_summary_makes_empty_default_deny_explicit(self):
        raw = config_fixture()
        raw['firewall'] = {'default_action': 'deny'}
        self.config_path.write_text(yaml.safe_dump(raw))
        code, output, _ = self.invoke(['check', '--config', str(self.config_path)])
        self.assertEqual(code, 0)
        self.assertIn('enforce 將封鎖所有網站請求', output)

    def test_deployment_has_only_frontend_port_and_readonly_tls_mounts(self):
        config = self.config | {'listener': self.config['listener'] | {'tls': {
            'certificate': '/private/certs/site.pem', 'private_key': '/private/certs/$secret.pem'}},
            'upstream': self.config['upstream'] | {'tls_ca_file': '/private/certs/ca.pem'}}
        service = deployment.compose_config(config)['services']['gateway']
        self.assertRegex(service['image'], r'^siteguard-gateway:[a-f0-9]{64}$')
        self.assertRegex(deployment.GATEWAY_DOCKERFILE, r'FROM envoyproxy/envoy:.*@sha256:[a-f0-9]{64}')
        self.assertEqual(service['build']['context'], './gateway')
        self.assertEqual(service['ports'], [{'target': 8080, 'published': '8088',
                                             'host_ip': '127.0.0.1', 'protocol': 'tcp'}])
        self.assertTrue(service['read_only'])
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertEqual(service['security_opt'], ['no-new-privileges:true'])
        self.assertEqual(service['restart'], 'unless-stopped')
        self.assertEqual(service['logging']['options']['max-file'], '3')
        self.assertIn('http://127.0.0.1:9901/ready', service['healthcheck']['test'])
        mounts = {item['target']: item for item in service['volumes']}
        self.assertEqual(mounts['/etc/siteguard/tls/private-key.pem']['source'], '/private/certs/$$secret.pem')
        self.assertTrue(all(item['read_only'] for item in mounts.values()))
        self.assertTrue(all(not item['bind']['create_host_path'] for item in mounts.values()))
        self.assertNotIn('admin.token', json.dumps(service))
        self.assertNotIn('9901', json.dumps(service['ports']))
        policy = deployment.compose_config(config)['services']['policy']
        self.assertNotIn('ports', policy)
        self.assertEqual(policy['networks'], ['policy'])
        self.assertTrue(deployment.compose_config(config)['networks']['policy']['internal'])

    def test_bundle_build_context_is_small_and_does_not_copy_tls_or_lab(self):
        config = self.config | {'listener': self.config['listener'] | {'tls': {
            'certificate': '/private/certs/site.pem', 'private_key': '/private/certs/private.pem'}}}
        deployment.render_files(config, self.output)
        self.assertEqual({path.name for path in (self.output / 'gateway').iterdir()},
                         {'Dockerfile', '.dockerignore'})
        self.assertEqual({path.name for path in (self.output / 'policy').iterdir()},
                         {'Dockerfile', 'requirements.txt', 'ratelimit.py', 'inspection.py', '.dockerignore'})
        self.assertEqual((self.output / 'policy' / '.dockerignore').read_text(),
                         '*\n!Dockerfile\n!requirements.txt\n!ratelimit.py\n!inspection.py\n')
        self.assertNotIn('/private/certs', (self.output / 'gateway' / 'Dockerfile').read_text())
        self.assertNotIn('lab', (self.output / 'policy' / 'Dockerfile').read_text())
        self.assertEqual(json.loads((self.output / 'policy.json').read_text()), {'mode': 'observe'})

    def test_only_gateway_joins_existing_origin_network_and_down_preserves_external_network(self):
        config = self.config | {'upstream': {'url': 'http://wordpress:80', 'network': 'my-app-network'}}
        compose = deployment.compose_config(config)
        self.assertEqual(compose['networks']['existing-origin'],
                         {'external': True, 'name': 'my-app-network'})
        self.assertIn('existing-origin', compose['services']['gateway']['networks'])
        self.assertNotIn('existing-origin', compose['services']['policy']['networks'])
        deployment.render_files(config, self.output)
        with patch.object(deployment, 'docker_command', return_value='') as run:
            deployment.down(self.output)
        self.assertEqual(run.call_args.args[0][-3:], ['down', '--timeout', '30'])
        self.assertNotIn('--volumes', run.call_args.args[0])

    def test_up_validates_real_envoy_before_starting_and_uses_argv(self):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if 'inspect' in argv:
                return subprocess.CompletedProcess(argv, 1, stdout='', stderr='image missing')
            if 'run' in argv:
                candidate = Path(argv[argv.index('--file') + 1])
                self.assertTrue(candidate.is_file())
                self.assertFalse((self.output / 'compose.yaml').exists())
            elif 'up' in argv:
                self.assertTrue((self.output / 'compose.yaml').exists())
            return subprocess.CompletedProcess(argv, 0, stdout='', stderr='')

        with patch.object(deployment.subprocess, 'run', side_effect=run):
            deployment.up(self.config, self.output, 'context with spaces', wait_timeout=45)
        self.assertEqual(len(calls), 6)
        self.assertIn('--filter', calls[0][0])
        self.assertEqual(calls[3][0][-3:], ['build', 'gateway', 'policy'])
        validate, start = calls[4][0], calls[5][0]
        self.assertEqual(validate[:3], ['docker', '--context', 'context with spaces'])
        self.assertIn('--mode', validate)
        self.assertEqual(validate[validate.index('--mode') + 1], 'validate')
        self.assertNotIn('--service-ports', validate)
        self.assertIn('--rm', validate)
        self.assertEqual(start[-9:], ['up', '-d', '--no-build', '--pull', 'never', '--force-recreate',
                                     '--wait', '--wait-timeout', '45'])
        self.assertTrue(all('shell' not in kwargs for _, kwargs in calls))

    def test_failed_validation_never_starts_or_replaces_previous_deployment(self):
        deployment.render_files(self.config, self.output)
        (self.output / 'envoy.yaml').write_text('previous envoy')
        compose_before = (self.output / 'compose.yaml').read_text()
        failure = subprocess.CompletedProcess([], 1, stdout='', stderr='invalid Envoy config')
        success = subprocess.CompletedProcess([], 0, stdout='', stderr='')
        with patch.object(deployment.subprocess, 'run', side_effect=[success, success, success, failure]) as run:
            with self.assertRaisesRegex(deployment.DeploymentError, 'invalid Envoy config'):
                deployment.up(self.config, self.output, 'test-context')
            self.assertEqual(run.call_count, 4)
        self.assertEqual((self.output / 'envoy.yaml').read_text(), 'previous envoy')
        self.assertEqual((self.output / 'compose.yaml').read_text(), compose_before)
        self.assertEqual(list(self.root.glob('.siteguard-validate-*')), [])

    def test_build_failure_does_not_validate_or_write_deployment(self):
        failure = subprocess.CompletedProcess([], 1, stdout='', stderr='image unavailable')
        success = subprocess.CompletedProcess([], 0, stdout='', stderr='')
        with patch.object(deployment.subprocess, 'run', side_effect=[success, failure, failure, failure]) as run:
            with self.assertRaisesRegex(deployment.DeploymentError, 'image unavailable'):
                deployment.up(self.config, self.output, 'test-context')
            self.assertEqual(run.call_count, 4)
        self.assertFalse((self.output / 'compose.yaml').exists())
        self.assertFalse((self.output / 'envoy.yaml').exists())
        self.assertIsNone(deployment.active_receipt(self.output))

    def lock_holder(self):
        script = '''
import sys
from pathlib import Path
from siteguard.deployment import deployment_lock
with deployment_lock(Path(sys.argv[1])):
    print('LOCKED', flush=True)
    sys.stdin.buffer.read(1)
'''
        process = subprocess.Popen([sys.executable, '-c', script, str(self.output)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)

        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

        self.addCleanup(cleanup)
        readable, _, _ = select.select([process.stdout], [], [], 5)
        self.assertTrue(readable, 'lock holder did not become ready')
        self.assertEqual(process.stdout.readline().strip(), 'LOCKED')
        return process

    @unittest.skipUnless(deployment.fcntl is not None, 'requires Linux/macOS flock')
    def test_real_cross_process_lock_blocks_all_mutations_but_not_readonly_commands(self):
        deployment.render_files(self.config, self.output)
        self.config_path.write_text(yaml.safe_dump(self.config))
        holder = self.lock_holder()
        for command in ('up', 'rollback', 'down', 'render'):
            result = subprocess.run([sys.executable, '-m', 'siteguard', command,
                                     '--config', str(self.config_path), '--output', str(self.output)],
                                    capture_output=True, text=True, timeout=5,
                                    env={**os.environ, 'PATH': '/nonexistent-siteguard-test-path'})
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('另一個操作正在進行', result.stderr)
        with patch.object(deployment, 'docker_command', return_value='[]'):
            self.assertEqual(deployment.status(self.output)['containers'], [])
            deployment.logs(self.output)
        holder.stdin.write('x')
        holder.stdin.flush()
        self.assertEqual(holder.wait(timeout=5), 0)
        with deployment.deployment_lock(self.output):
            self.assertEqual((self.output / '.siteguard').stat().st_mode & 0o777, 0o700)
            self.assertEqual((self.output / '.siteguard/operation.lock').stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(deployment.fcntl is not None, 'requires Linux/macOS flock')
    def test_kernel_releases_lock_when_holder_is_killed_without_stale_pid_cleanup(self):
        holder = self.lock_holder()
        holder.kill()
        holder.wait(timeout=5)
        self.assertTrue((self.output / '.siteguard/operation.lock').is_file())
        with deployment.deployment_lock(self.output):
            pass
        deployment.render_files(self.config, self.output)
        self.assertTrue((self.output / 'compose.yaml').is_file())

    def successful_up(self, config=None):
        with patch.object(deployment, 'docker_command', side_effect=lambda argv, **kwargs:
                          '' if '--filter' in argv else 'sha256:existing-image') as run:
            deployment.up(config or self.config, self.output, 'test-context')
        return run.call_args_list

    def second_config(self):
        return self.config | {'listener': {'host': '127.0.0.1', 'port': 8089}}

    def history(self):
        return [json.loads(line) for line in
                (self.output / '.siteguard' / 'history.jsonl').read_text().splitlines()]

    def test_content_tags_change_only_when_image_source_changes_and_existing_tags_are_not_rebuilt(self):
        before = deployment.compose_config(self.config, source='policy version one')
        after = deployment.compose_config(self.config, source='policy version two')
        self.assertEqual(before['services']['gateway']['image'], after['services']['gateway']['image'])
        self.assertNotEqual(before['services']['policy']['image'], after['services']['policy']['image'])
        calls = self.successful_up()
        self.assertFalse(any('build' in call.args[0] for call in calls))

    def test_successful_updates_preserve_previous_complete_snapshot_and_force_restart(self):
        self.successful_up()
        first = deployment.active_receipt(self.output)
        first_compose = (self.output / 'compose.yaml').read_bytes()
        calls = self.successful_up(self.second_config())
        second = deployment.active_receipt(self.output)
        self.assertNotEqual(first['version'], second['version'])
        self.assertEqual(second['previous_version'], first['version'])
        old = deployment.saved_bundle(self.output, first['version'])
        self.assertEqual((old / 'compose.yaml').read_bytes(), first_compose)
        self.assertTrue((old / 'policy/ratelimit.py').is_file())
        self.assertIn('--force-recreate', next(call.args[0] for call in calls if 'up' in call.args[0]))
        self.assertEqual([row['status'] for row in self.history()], ['complete', 'complete'])

    def legacy_snapshot(self):
        version = 'c12ba9e7adad970fce2f65b796178479de882d072f3f8d008cf1bb582da49bdb'
        folder = self.output / '.siteguard' / 'versions' / version
        names = ('envoy.yaml', 'compose.yaml', 'policy.json', 'gateway/Dockerfile',
                 'gateway/.dockerignore', 'policy/Dockerfile', 'policy/.dockerignore',
                 'policy/requirements.txt', 'policy/ratelimit.py')
        for name in names:
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f'legacy 0.1 fixture: {name}\n')
        return version, folder

    def test_legacy_snapshot_preserves_original_hash_without_inspection_module(self):
        version, folder = self.legacy_snapshot()
        before = {path.relative_to(folder): path.read_bytes() for path in folder.rglob('*') if path.is_file()}
        self.assertEqual(deployment.bundle_hash(folder), version)
        self.assertEqual(deployment.saved_bundle(self.output, version), folder)
        self.assertFalse((folder / 'policy/inspection.py').exists())
        self.assertEqual({path.relative_to(folder): path.read_bytes()
                          for path in folder.rglob('*') if path.is_file()}, before)

    def test_new_snapshot_missing_inspection_cannot_pass_as_legacy(self):
        deployment.render_files(self.config, self.output)
        version, folder = deployment.save_bundle(self.output, self.output)
        for name in ('policy/inspection.py', 'policy/ratelimit.py'):
            with self.subTest(missing=name):
                path = folder / name
                content = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(deployment.DeploymentError, '部署快照遺失或已變更'):
                    deployment.saved_bundle(self.output, version)
                path.write_bytes(content)
        self.assertEqual(deployment.saved_bundle(self.output, version), folder)

    def test_copy_new_legacy_and_new_removes_stale_generated_files_without_changing_snapshots(self):
        legacy_version, legacy = self.legacy_snapshot()
        current = self.root / 'current-candidate'
        deployment.render_files(self.config, current)
        current_version = deployment.bundle_hash(current)
        target = self.root / 'active-bundle'
        deployment.copy_bundle(current, target)
        self.assertTrue((target / 'policy/inspection.py').is_file())
        (target / 'operator-note.txt').write_text('keep this unrelated file')
        deployment.copy_bundle(legacy, target)
        self.assertFalse((target / 'policy/inspection.py').exists())
        self.assertEqual(deployment.bundle_hash(target), legacy_version)
        self.assertEqual(deployment.bundle_hash(current), current_version)
        self.assertEqual(deployment.saved_bundle(self.output, legacy_version), legacy)
        deployment.copy_bundle(current, target)
        self.assertEqual((target / 'policy/inspection.py').read_bytes(),
                         (current / 'policy/inspection.py').read_bytes())
        self.assertEqual(deployment.bundle_hash(target), current_version)
        self.assertEqual(deployment.bundle_hash(legacy), legacy_version)
        self.assertEqual((target / 'operator-note.txt').read_text(), 'keep this unrelated file')

    def test_failed_update_restores_last_success_and_preserves_failure_diagnostics(self):
        self.successful_up()
        first = deployment.active_receipt(self.output)
        first_bytes = (self.output / 'compose.yaml').read_bytes()
        starts = []

        def docker(argv, **kwargs):
            if '--filter' in argv:
                return ''
            if 'up' in argv:
                port = yaml.safe_load((self.output / 'compose.yaml').read_text())['services']['gateway']['ports'][0]['published']
                starts.append(port)
                if port == '8089':
                    raise deployment.DeploymentError('candidate health check failed')
            return 'diagnostic container state'

        with patch.object(deployment, 'docker_command', side_effect=docker):
            with self.assertRaisesRegex(deployment.DeploymentError, '已恢復前一成功版本'):
                deployment.up(self.second_config(), self.output, 'test-context')
        self.assertEqual(starts, ['8089', '8088'])
        self.assertEqual(deployment.active_receipt(self.output), first)
        self.assertEqual((self.output / 'compose.yaml').read_bytes(), first_bytes)
        failed = self.history()[-1]
        self.assertEqual(failed['status'], 'failed_recovered')
        diagnostic = json.loads(Path(failed['diagnostic']).read_text())
        self.assertIn('candidate health check failed', diagnostic['error'])
        self.assertEqual(diagnostic['logs'], 'diagnostic container state')

    def test_first_failed_up_preserves_bundle_and_diagnostics_without_removing_services(self):
        calls = []

        def docker(argv, **kwargs):
            calls.append(argv)
            if '--filter' in argv:
                return ''
            if 'up' in argv:
                raise deployment.DeploymentError('port already allocated')
            return 'diagnostic'

        with patch.object(deployment, 'docker_command', side_effect=docker):
            with self.assertRaisesRegex(deployment.DeploymentError, '首次部署失敗'):
                deployment.up(self.config, self.output, 'test-context')
        self.assertIsNone(deployment.active_receipt(self.output))
        self.assertTrue((self.output / 'compose.yaml').is_file())
        self.assertEqual(self.history()[-1]['status'], 'failed_no_previous')
        self.assertTrue(Path(self.history()[-1]['diagnostic']).is_file())
        self.assertFalse(any('down' in argv for argv in calls))
        command = deployment.compose_argv(self.output)
        self.assertEqual(command[command.index('--context') + 1], 'test-context')

    def test_rollback_uses_saved_bundle_without_loading_new_user_config(self):
        self.successful_up()
        first = deployment.active_receipt(self.output)
        self.successful_up(self.second_config())
        second = deployment.active_receipt(self.output)
        with patch.object(cli, 'load_config', side_effect=AssertionError('rollback needs no new config')):
            with patch.object(deployment, 'docker_command', return_value='') as run:
                code, _, error = self.invoke(['rollback', '--output', str(self.output)])
        self.assertEqual((code, error), (0, ''))
        current = deployment.active_receipt(self.output)
        self.assertEqual(current['version'], first['version'])
        self.assertEqual(current['previous_version'], second['version'])
        self.assertEqual(self.history()[-1]['action'], 'rollback')
        self.assertEqual(self.history()[-1]['status'], 'complete')
        self.assertFalse(any('build' in call.args[0] for call in run.call_args_list))

    def test_failed_rollback_validation_leaves_successful_version_in_place(self):
        self.successful_up()
        self.successful_up(self.second_config())
        current = deployment.active_receipt(self.output)
        def docker(argv, **kwargs):
            if '--filter' in argv:
                return ''
            raise deployment.DeploymentError('missing prior image')

        with patch.object(deployment, 'docker_command', side_effect=docker):
            with self.assertRaisesRegex(deployment.DeploymentError, 'missing prior image'):
                deployment.rollback(self.output)
        self.assertEqual(deployment.active_receipt(self.output), current)
        self.assertEqual(deployment.bundle_hash(self.output), current['version'])

    def test_owned_project_and_empty_project_allow_mutation(self):
        deployment.render_files(self.config, self.output)
        owner = json.dumps({'com.docker.compose.project.working_dir': str(self.output.resolve())})
        with patch.object(deployment, 'docker_command', side_effect=['abcdef123456', owner, '']) as run:
            deployment.down(self.output, 'test-context')
        self.assertEqual(run.call_args_list[-1].args[0][-3:], ['down', '--timeout', '30'])
        self.assertIn('label=com.docker.compose.project=siteguard', run.call_args_list[0].args[0])
        self.assertIn('{{json .Config.Labels}}', run.call_args_list[1].args[0])
        calls = self.successful_up()
        self.assertTrue(any('up' in call.args[0] for call in calls))

    def test_foreign_or_unlabelled_project_refuses_up_rollback_down_even_with_local_receipt(self):
        self.successful_up()
        self.successful_up(self.second_config())
        before = (self.output / 'compose.yaml').read_bytes()
        receipt = deployment.active_receipt(self.output)
        for labels in ({'com.docker.compose.project.working_dir': str(self.root / 'another-website')}, {}):
            for operation in (lambda: deployment.up(self.config, self.output),
                              lambda: deployment.rollback(self.output),
                              lambda: deployment.down(self.output)):
                with patch.object(deployment, 'docker_command',
                                  side_effect=['abcdef123456', json.dumps(labels)]) as run:
                    with self.assertRaisesRegex(deployment.DeploymentError, '請使用不同的 name／output'):
                        operation()
                self.assertEqual(run.call_count, 2)
                self.assertTrue(all(not {'up', 'run', 'build', 'down'}.intersection(call.args[0])
                                    for call in run.call_args_list))
        self.assertEqual(deployment.active_receipt(self.output), receipt)
        self.assertEqual((self.output / 'compose.yaml').read_bytes(), before)

    def test_failed_ownership_observation_and_unmanaged_compose_fail_without_changes(self):
        for responses in ([deployment.DeploymentError('daemon inaccessible')],
                          ['abcdef123456', ''], ['unexpected non-container output']):
            with patch.object(deployment, 'docker_command', side_effect=responses) as run:
                with self.assertRaises(deployment.DeploymentError):
                    deployment.up(self.config, self.output, 'test-context')
                self.assertTrue(all(not {'up', 'run', 'build', 'down'}.intersection(call.args[0])
                                    for call in run.call_args_list))
        self.assertFalse((self.output / 'compose.yaml').exists())
        unrelated = 'name: another-website\nservices:\n  wordpress:\n    image: wordpress\n'
        (self.output / 'compose.yaml').write_text(unrelated)
        for operation in (lambda: deployment.render_files(self.config, self.output),
                          lambda: deployment.up(self.config, self.output, 'test-context'),
                          lambda: deployment.down(self.output, 'test-context')):
            with patch.object(deployment, 'docker_command') as run:
                with self.assertRaisesRegex(deployment.DeploymentError, '不屬於 SiteGuard'):
                    operation()
                run.assert_not_called()
        self.assertEqual((self.output / 'compose.yaml').read_text(), unrelated)

    def test_failed_recovery_is_reported_without_claiming_a_successful_restore(self):
        self.successful_up()

        def docker(argv, **kwargs):
            if 'up' in argv:
                raise deployment.DeploymentError('daemon stopped')
            return ''

        with patch.object(deployment, 'docker_command', side_effect=docker):
            with self.assertRaisesRegex(deployment.DeploymentError, '前一版本也未能恢復'):
                deployment.up(self.second_config(), self.output)
        self.assertEqual(self.history()[-1]['status'], 'recovery_failed')

    def test_render_cannot_overwrite_managed_deployment_and_context_name_are_bound(self):
        self.successful_up()
        before = (self.output / 'compose.yaml').read_bytes()
        with self.assertRaisesRegex(deployment.DeploymentError, '請用 up 更新'):
            deployment.render_files(self.second_config(), self.output)
        with patch.object(deployment, 'docker_command') as run:
            with self.assertRaisesRegex(deployment.DeploymentError, '另一個 Docker context'):
                deployment.up(self.config, self.output, 'different-context')
            with self.assertRaisesRegex(deployment.DeploymentError, '變更 name'):
                deployment.up(self.config | {'name': 'another'}, self.output)
            run.assert_not_called()
        self.assertEqual((self.output / 'compose.yaml').read_bytes(), before)
        command = deployment.compose_argv(self.output)
        self.assertEqual(command[command.index('--context') + 1], 'test-context')

    def test_snapshots_store_mount_references_but_never_copy_private_key(self):
        key = self.root / 'key.pem'
        key.write_text('PRIVATE KEY CONTENT MUST NOT BE COPIED')
        tls_config = self.config | {'listener': self.config['listener'] | {'tls': {
            'certificate': '/private/certificate.pem', 'private_key': str(key)}}}
        self.successful_up(tls_config)
        snapshot = deployment.saved_bundle(self.output, deployment.active_receipt(self.output)['version'])
        for path in snapshot.rglob('*'):
            if path.is_file():
                self.assertNotIn(key.read_bytes(), path.read_bytes())
        compose = yaml.safe_load((snapshot / 'compose.yaml').read_text())
        mounts = compose['services']['gateway']['volumes']
        self.assertEqual(next(mount['source'] for mount in mounts if mount['target'].endswith('private-key.pem')),
                         str(key))

    def test_status_reports_actual_docker_state_and_unknown_readiness(self):
        deployment.render_files(self.config, self.output)
        rows = [{'Name': 'siteguard-gateway-1', 'Service': 'gateway', 'State': 'running', 'Health': ''},
                {'Name': 'siteguard-policy-1', 'Service': 'policy', 'State': 'running', 'Health': ''}]
        with patch.object(deployment, 'docker_command', return_value=json.dumps(rows)) as run:
            result = deployment.status(self.output)
        self.assertTrue(result['running'])
        self.assertIsNone(result['ready'])
        self.assertEqual(result['containers'], rows)
        self.assertEqual(run.call_args.args[0][-4:], ['ps', '--all', '--format', 'json'])
        rows[0]['State'] = 'restarting'
        with patch.object(deployment, 'docker_command', return_value=json.dumps(rows[0])):
            result = deployment.status(self.output)
        self.assertFalse(result['running'])
        self.assertFalse(result['ready'])
        healthy = [{'Service': 'gateway', 'State': 'running', 'Health': 'healthy'},
                   {'Service': 'policy', 'State': 'running', 'Health': 'healthy'}]
        with patch.object(deployment, 'docker_command', return_value=json.dumps(healthy)):
            self.assertTrue(deployment.status(self.output)['ready'])
        with patch.object(deployment, 'docker_command', return_value=json.dumps(healthy[:1])):
            state = deployment.status(self.output)
            self.assertFalse(state['ready'])
            self.assertEqual(state['missing_services'], ['policy'])

    def test_status_supports_compose_json_lines_and_empty_deployment(self):
        deployment.render_files(self.config, self.output)
        raw = '\n'.join(json.dumps({'State': state}) for state in ('running', 'exited'))
        with patch.object(deployment, 'docker_command', return_value=raw):
            self.assertFalse(deployment.status(self.output)['running'])
        with patch.object(deployment, 'docker_command', return_value=''):
            self.assertEqual(deployment.status(self.output)['containers'], [])

    def test_logs_and_down_use_rendered_deployment_without_loading_source_config(self):
        deployment.render_files(self.config, self.output)
        with patch.object(cli, 'load_config', side_effect=AssertionError('not needed')):
            with patch.object(deployment, 'docker_command', return_value='') as run:
                self.assertEqual(self.invoke(['logs', '--output', str(self.output),
                                              '--tail', '20', '--follow'])[0], 0)
                self.assertEqual(run.call_args.args[0][-5:],
                                 ['logs', '--no-color', '--tail', '20', '--follow'])
                self.assertEqual(run.call_args.kwargs, {'capture': False, 'timeout': None})
                self.invoke(['logs', '--output', str(self.output), '--service', 'policy'])
                self.assertEqual(run.call_args.args[0][-1], 'policy')
                self.assertEqual(self.invoke(['down', '--output', str(self.output)])[0], 0)
                self.assertEqual(run.call_args.args[0][-3:], ['down', '--timeout', '30'])
                self.assertNotIn('--volumes', run.call_args.args[0])

    def test_metrics_uses_container_admin_endpoint_without_publishing_port(self):
        deployment.render_files(self.config, self.output)
        with patch.object(deployment, 'docker_command', return_value='{}') as run:
            code, output, _ = self.invoke(['metrics', '--output', str(self.output)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output), {})
            self.assertIn('exec', run.call_args.args[0])
            self.assertEqual(run.call_args.args[0][-1], 'http://127.0.0.1:9901/stats?format=json')
            self.invoke(['metrics', '--output', str(self.output), '--format', 'prometheus'])
            self.assertEqual(run.call_args.args[0][-1], 'http://127.0.0.1:9901/stats/prometheus')

    def test_project_name_is_explicit_and_cannot_be_changed_by_shell_environment(self):
        deployment.render_files(self.config, self.output)
        with patch.dict(deployment.os.environ, {'COMPOSE_PROJECT_NAME': 'unrelated-project'}):
            command = deployment.compose_argv(self.output)
        self.assertEqual(command[command.index('--project-name') + 1], 'siteguard')
        self.assertEqual(command[command.index('--env-file') + 1], deployment.os.devnull)

    def test_missing_docker_and_invalid_config_fail_with_readable_errors(self):
        with patch.object(deployment.subprocess, 'run', side_effect=FileNotFoundError):
            with self.assertRaisesRegex(deployment.DeploymentError, '找不到 Docker CLI'):
                deployment.docker_command(['docker', 'version'])
        with patch.object(cli, 'load_config', side_effect=ValueError('invalid policy')):
            code, _, stderr = self.invoke(['check'])
            self.assertEqual(code, 1)
            self.assertIn('invalid policy', stderr)


if __name__ == '__main__':
    unittest.main()
