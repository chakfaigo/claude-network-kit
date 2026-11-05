"""Exercise actual ensure_pf with fake PF and a strict temporary write jail."""

from contextlib import ExitStack
import builtins
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock


PACKAGE = Path(__file__).resolve().parent
BASE = '''scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
'''
APPLE_ACTIVE = ('scrub-anchor "com.apple/*" all fragment reassemble\n'
                'anchor "com.apple/*" all\n'
                'dummynet-anchor "com.apple/*" all\n')


class EnsurePFTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='.pf-runtime-test-', dir=PACKAGE)
        self.base = Path(self.tmp.name).resolve()
        self.stack = ExitStack()
        self._block_effects()
        self.runtime = self.load('guard_runtime')
        self.pf = self.load('guard_pf')
        self.private = self.base / 'private'
        self.private.mkdir()
        self.etc = self.base / 'etc'
        self.etc.mkdir()
        self.conf = self.etc / 'pf.conf'
        self.anchor_file = self.etc / self.pf.ANCHOR_NAME
        self.conf.write_text(self.pf.prepare_pf_conf(BASE))
        self.anchor_file.write_text(self.pf.render_anchor())
        self.token = self.private / 'pf-token.json'
        self.record = self.private / 'pf-active.json'
        self.main = APPLE_ACTIVE
        self.guarded_main = APPLE_ACTIVE.replace('\nanchor "com.apple/*" all\n',
            f'\nanchor "{self.pf.ANCHOR_NAME}" all\nanchor "com.apple/*" all\n')
        self.active_anchor = ''
        self.enabled = False
        self.references = ['999']
        self.interfaces = 'lo0\nen0\nutun99\n'
        self.fail_anchor = self.fail_flush = self.no_token = False
        self.calls = []

        def mapped_path(path):
            original = Path(path)
            if str(original) == '/etc/pf.conf':
                return self.conf
            if str(original) == self.pf.ANCHOR_FILE:
                return self.anchor_file
            return original

        for name, value in (('PRIVATE', self.private), ('Path', mapped_path),
                            ('trusted', self.trusted), ('command', self.command)):
            self.stack.enter_context(mock.patch.object(self.runtime, name, value))

    def tearDown(self):
        self.stack.close()
        self.tmp.cleanup()

    def load(self, name):
        spec = importlib.util.spec_from_file_location(name + '_pf_test', PACKAGE / (name + '.py'))
        result = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(result)
        return result

    def _block_effects(self):
        def denied(*args, **kwargs):
            raise AssertionError('REAL EXTERNAL OPERATION BLOCKED')

        for obj, name in ((subprocess, 'run'), (subprocess, 'Popen'),
                          (socket, 'socket'), (socket, 'create_connection'),
                          (os, 'system'), (os, 'kill'), (os, 'killpg'),
                          (os, 'posix_spawn'), (os, 'posix_spawnp')):
            self.stack.enter_context(mock.patch.object(obj, name, denied))

        def check(path):
            if isinstance(path, int):
                return
            if not Path(os.fsdecode(path)).resolve().is_relative_to(self.base):
                raise AssertionError('WRITE OUTSIDE TEMP FIXTURE BLOCKED')

        for obj in (builtins, io):
            original = obj.open

            def open_file(path, mode='r', *args, _call=original, **kwargs):
                if any(flag in mode for flag in 'wax+'):
                    check(path)
                return _call(path, mode, *args, **kwargs)
            self.stack.enter_context(mock.patch.object(obj, 'open', open_file))
        original_open = os.open

        def os_open(path, flags, *args, **kwargs):
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                check(path)
            return original_open(path, flags, *args, **kwargs)
        self.stack.enter_context(mock.patch.object(os, 'open', os_open))
        for name in ('mkdir', 'chmod', 'chown', 'unlink', 'remove', 'rmdir', 'utime'):
            original = getattr(os, name)

            def one_path(path, *args, _call=original, **kwargs):
                check(path)
                return _call(path, *args, **kwargs)
            self.stack.enter_context(mock.patch.object(os, name, one_path))
        for name in ('replace', 'rename', 'link'):
            original = getattr(os, name)

            def two_paths(source, target, *args, _call=original, **kwargs):
                check(source)
                check(target)
                return _call(source, target, *args, **kwargs)
            self.stack.enter_context(mock.patch.object(os, name, two_paths))

    def trusted(self, path, directory=False):
        self.assertTrue(Path(path).resolve().is_relative_to(self.base))
        self.assertFalse(Path(path).is_symlink())
        self.assertEqual(Path(path).is_dir(), directory)

    def command(self, args, check=True, timeout=20):
        args = tuple(str(item) for item in args)
        self.assertEqual(args[0], '/sbin/pfctl')
        tail = args[1:]
        self.calls.append(tail)
        output, error = '', ''
        if tail == ('-s', 'info'):
            output = 'Status: ' + ('Enabled' if self.enabled else 'Disabled')
        elif tail == ('-sr',):
            output = self.main
        elif tail == ('-s', 'Interfaces', '-v'):
            output = self.interfaces
        elif tail == ('-a', self.pf.ANCHOR_NAME, '-sr'):
            output = self.active_anchor
        elif tail == ('-s', 'References'):
            output = '\n'.join('pid 77 token ' + token for token in self.references)
        elif tail == ('-f', '/etc/pf.conf'):
            self.main = self.guarded_main
            self.active_anchor = self.pf.render_anchor()
        elif tail == ('-a', self.pf.ANCHOR_NAME, '-f', self.pf.ANCHOR_FILE):
            if self.fail_anchor:
                raise RuntimeError('simulated anchor load failure')
            self.active_anchor = self.pf.render_anchor()
        elif tail == ('-E',):
            self.enabled = True
            if not self.no_token:
                self.references.append('123456')
                error = 'pf enabled\nToken : 123456\n'
        elif tail == ('-F', 'states'):
            self.assertTrue(self.enabled)
            self.pf.validate_runtime_main_filter(self.main)
            self.assertTrue(self.active_anchor)
            self.assertTrue(json.loads(self.record.read_text())['states_pending'])
            if self.fail_flush:
                self.fail_flush = False
                raise RuntimeError('simulated state flush failure')
        else:
            raise AssertionError('UNEXPECTED PF COMMAND: ' + repr(tail))
        return SimpleNamespace(returncode=0, stdout=output, stderr=error)

    def healthy(self):
        self.main = self.guarded_main
        self.active_anchor = self.pf.render_anchor()
        self.enabled = True
        self.references.append('123456')
        self.token.write_text(json.dumps({'token': '123456'}))
        self.record.write_text(json.dumps({'digest': hashlib.sha256(self.active_anchor.strip().encode()).hexdigest()}))
        self.assertTrue(self.runtime.guard_ok(self.pf))
        self.calls.clear()

    def mutations(self):
        return [args for args in self.calls if args in (('-f', '/etc/pf.conf'), ('-E',), ('-F', 'states'))
                or args == ('-a', self.pf.ANCHOR_NAME, '-f', self.pf.ANCHOR_FILE)]

    def test_initial_install_enables_owns_token_and_flushes_after_guard(self):
        self.runtime.ensure_pf(self.pf, initial=True)
        mutations = self.mutations()
        self.assertEqual(mutations, [('-f', '/etc/pf.conf'),
            ('-a', self.pf.ANCHOR_NAME, '-f', self.pf.ANCHOR_FILE), ('-E',), ('-F', 'states')])
        self.assertEqual(json.loads(self.token.read_text())['token'], '123456')
        self.assertTrue(self.runtime.guard_ok(self.pf))
        self.assertNotIn('states_pending', json.loads(self.record.read_text()))

    def test_missing_guard_at_service_start_flushes_without_initial_flag(self):
        self.enabled = True  # Another component already owns a PF reference.
        self.runtime.ensure_pf(self.pf)
        self.assertEqual(self.calls.count(('-F', 'states')), 1)
        self.assertIn(('-E',), self.calls)
        self.assertTrue(self.runtime.guard_ok(self.pf))

    def test_disabled_pf_after_reboot_reacquires_token_and_flushes(self):
        self.healthy()
        self.enabled = False
        self.references = ['999']
        self.runtime.ensure_pf(self.pf)
        self.assertIn(('-E',), self.calls)
        self.assertEqual(self.calls.count(('-F', 'states')), 1)

    def test_lost_anchor_and_digest_change_both_require_flush(self):
        for broken_anchor in ('', self.pf.render_anchor() + '# changed\n'):
            with self.subTest(anchor=broken_anchor):
                self.healthy()
                self.active_anchor = broken_anchor
                self.runtime.ensure_pf(self.pf)
                self.assertEqual(self.calls.count(('-F', 'states')), 1)
                self.assertTrue(self.runtime.guard_ok(self.pf))

    def test_healthy_repeated_core_or_mode_start_never_flushes(self):
        self.healthy()
        self.runtime.ensure_pf(self.pf)
        self.runtime.ensure_pf(self.pf)
        self.assertNotIn(('-F', 'states'), self.calls)
        self.assertNotIn(('-E',), self.calls)
        self.assertNotIn(('-f', '/etc/pf.conf'), self.calls)

    def test_concurrent_ensure_waits_until_first_cache_commit(self):
        self.healthy()
        first_at_commit = threading.Event()
        release_first = threading.Event()
        second_at_lock = threading.Event()
        second_executed_command = threading.Event()
        original_replace = os.replace
        original_flock = fcntl.flock
        errors = []

        def replace(source, target):
            if Path(target) == self.record and threading.current_thread().name == 'pf-first':
                first_at_commit.set()
                if not release_first.wait(timeout=3):
                    raise AssertionError('first cache commit was not released')
            return original_replace(source, target)

        def flock(fd, operation):
            if threading.current_thread().name == 'pf-second' and operation & fcntl.LOCK_EX:
                second_at_lock.set()
            return original_flock(fd, operation)

        def command(*args, **kwargs):
            if threading.current_thread().name == 'pf-second':
                second_executed_command.set()
            return self.command(*args, **kwargs)

        def ensure():
            try:
                self.runtime.ensure_pf(self.pf)
            except BaseException as exc:
                errors.append(exc)

        workers = [threading.Thread(name=name, target=ensure, daemon=True)
                   for name in ('pf-first', 'pf-second')]
        with mock.patch.object(os, 'replace', replace), \
                mock.patch.object(fcntl, 'flock', flock), \
                mock.patch.object(self.runtime, 'command', command):
            try:
                workers[0].start()
                self.assertTrue(first_at_commit.wait(timeout=2))
                workers[1].start()
                self.assertTrue(second_at_lock.wait(timeout=2))
                # The second caller reached the real lock while the first has
                # not committed its fixed-name temporary cache file yet.
                self.assertFalse(second_executed_command.wait(timeout=0.05))
            finally:
                release_first.set()
                for worker in workers:
                    if worker.ident is not None:
                        worker.join(timeout=3)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(errors, [])
        self.assertTrue(second_executed_command.is_set())
        self.assertTrue(self.runtime.guard_ok(self.pf))
        self.assertNotIn(('-F', 'states'), self.calls)

    def test_ensure_exception_releases_lock_before_retry(self):
        self.healthy()
        self.fail_anchor = True
        with self.assertRaisesRegex(RuntimeError, 'anchor load'):
            self.runtime.ensure_pf(self.pf)
        # A separate descriptor must be able to acquire the kernel lock;
        # the retry must not deadlock after an exception inside the operation.
        fd = os.open(self.private / 'pf.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
        self.fail_anchor = False
        self.runtime.ensure_pf(self.pf)
        self.assertTrue(self.runtime.guard_ok(self.pf))

    def test_atomic_json_concurrent_writers_commit_complete_files_without_leftovers(self):
        target = self.private / 'concurrent.json'
        before = set(self.private.iterdir())
        payloads = [{'writer': 1, 'data': ['甲' * 1024, {'count': 37}]},
                    {'writer': 2, 'data': ['乙' * 67, {'count': 9021}]}]
        at_replace = threading.Barrier(2)
        original_replace = os.replace
        sources, errors = [], []

        def replace(source, destination):
            if Path(destination) == target:
                sources.append(Path(source))
                # Both real temporary files have been written and fsynced;
                # neither can replace the destination before the other arrives.
                at_replace.wait(timeout=2)
            return original_replace(source, destination)

        def write(value):
            try:
                self.runtime.atomic_json(target, value)
            except BaseException as exc:
                errors.append(exc)

        workers = [threading.Thread(target=write, args=(value,), daemon=True)
                   for value in payloads]
        with mock.patch.object(os, 'replace', replace):
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=3)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(errors, [])
        self.assertEqual(len(set(sources)), 2)
        self.assertIn(json.loads(target.read_text()), payloads)
        self.assertEqual(set(self.private.iterdir()) - before, {target})
        self.assertTrue(all(not path.exists() for path in sources))

    def test_explicit_initial_flag_flushes_even_with_healthy_guard(self):
        self.healthy()
        self.runtime.ensure_pf(self.pf, initial=True)
        self.assertEqual(self.calls.count(('-F', 'states')), 1)

    def test_live_saved_token_is_reused(self):
        self.healthy()
        self.runtime.ensure_pf(self.pf)
        self.assertEqual(self.references, ['999', '123456'])
        self.assertNotIn(('-E',), self.calls)

    def test_missing_or_stale_own_token_is_acquired_despite_other_reference(self):
        for saved in (None, '12345'):
            with self.subTest(saved=saved):
                self.healthy()
                if saved is None:
                    self.token.unlink()
                else:
                    self.token.write_text(json.dumps({'token': saved}))
                self.runtime.ensure_pf(self.pf)
                self.assertEqual(self.calls.count(('-E',)), 1)
                self.assertNotIn(('-F', 'states'), self.calls)

    def test_corrupt_token_cache_reacquires_and_enables_disabled_pf(self):
        for content in ('{bad JSON', '[]', '{"token": 123456}',
                        '{"token": "not-a-token"}', '{"token": ""}',
                        '{"token": "１２３"}'):
            with self.subTest(content=content):
                self.enabled = False
                self.main = APPLE_ACTIVE
                self.active_anchor = ''
                self.references = ['999']
                self.calls.clear()
                self.token.write_text(content)
                self.runtime.ensure_pf(self.pf)
                self.assertTrue(self.enabled)
                self.assertEqual(self.calls.count(('-E',)), 1)
                self.assertEqual(self.calls.count(('-F', 'states')), 1)
                self.assertEqual(json.loads(self.token.read_text())['token'], '123456')
                self.assertTrue(self.runtime.guard_ok(self.pf))

    def test_unknown_main_filter_is_rejected_before_pf_mutation(self):
        self.healthy()
        self.main = 'pass out quick all\n' + self.main
        with self.assertRaises(ValueError):
            self.runtime.ensure_pf(self.pf)
        self.assertEqual(self.mutations(), [])

    def test_non_loopback_skip_is_rejected_before_anchor_load(self):
        self.healthy()
        self.interfaces = 'lo0 (skip)\nen0 (skip)\n'
        with self.assertRaisesRegex(RuntimeError, 'skip'):
            self.runtime.ensure_pf(self.pf)
        self.assertEqual(self.mutations(), [])

    def test_loopback_skip_remains_supported(self):
        self.healthy()
        self.interfaces = 'lo0 (skip)\nen0\nutun99\n'
        self.runtime.ensure_pf(self.pf)
        self.assertNotIn(('-F', 'states'), self.calls)

    def test_anchor_load_failure_does_not_enable_or_flush(self):
        self.fail_anchor = True
        with self.assertRaisesRegex(RuntimeError, 'anchor load'):
            self.runtime.ensure_pf(self.pf)
        self.assertNotIn(('-E',), self.calls)
        self.assertNotIn(('-F', 'states'), self.calls)
        self.assertFalse(self.runtime.guard_ok(self.pf))

    def test_state_flush_failure_stays_pending_and_retry_repeats_flush(self):
        self.healthy()
        self.active_anchor = ''
        self.fail_flush = True
        with self.assertRaisesRegex(RuntimeError, 'state flush'):
            self.runtime.ensure_pf(self.pf)
        self.assertFalse(self.runtime.guard_ok(self.pf))
        self.assertTrue(json.loads(self.record.read_text())['states_pending'])
        self.runtime.ensure_pf(self.pf)
        self.assertEqual(self.calls.count(('-F', 'states')), 2)
        self.assertTrue(self.runtime.guard_ok(self.pf))

    def test_missing_returned_token_refuses_success(self):
        self.no_token = True
        with self.assertRaisesRegex(RuntimeError, '引用未返回'):
            self.runtime.ensure_pf(self.pf)
        self.assertFalse(self.runtime.guard_ok(self.pf))
        self.assertNotIn(('-F', 'states'), self.calls)

    def test_changed_disk_anchor_is_rejected_before_pf_mutation(self):
        self.anchor_file.write_text('pass out all\n')
        with self.assertRaises(ValueError):
            self.runtime.ensure_pf(self.pf)
        self.assertEqual(self.mutations(), [])

    def test_harness_denies_external_calls_and_outside_writes(self):
        with self.assertRaises(AssertionError):
            subprocess.run(['/usr/bin/true'])
        with self.assertRaises(AssertionError):
            socket.socket()
        with self.assertRaises(AssertionError):
            Path('/tmp/pf-runtime-forbidden').write_text('forbidden')


if __name__ == '__main__':
    unittest.main()
