"""Startup evidence must never retain server output or credentials."""
import contextlib
import io
import json
import os
import threading
import unittest
from unittest.mock import patch
from policy_delta import runner
from policy_delta.__main__ import main


class StartupDiagnosticsTests(unittest.TestCase):
    def drain(self, chunks):
        read_fd, write_fd = os.pipe()
        ready, stop = threading.Event(), threading.Event()
        stats = runner._StartupDiagnostics()
        with os.fdopen(read_fd, 'rb', buffering=0) as output:
            worker = threading.Thread(target=runner._drain_server_output, args=(output, ready, stop, stats))
            worker.start()
            try:
                for chunk in chunks:
                    os.write(write_fd, chunk)
            finally:
                os.close(write_fd)
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        return ready, stats.snapshot()

    def test_chunked_marker_and_sensitive_output_keep_counts_only(self):
        chunks = [b'private-root-token secret-value\n==> OpenBao server sta', b'rted!\r\n']
        ready, stats = self.drain(chunks)
        self.assertTrue(ready.is_set())
        self.assertEqual(stats['complete_lines'], 2)
        self.assertEqual(stats['marker_lines'], 1)
        self.assertEqual(stats['drain_state'], 'eof')
        self.assertEqual(stats['bytes_seen'], sum(map(len, chunks)))
        for secret in ['private-root-token', 'secret-value']:
            self.assertNotIn(secret, json.dumps(stats))
        self.assertTrue(all(type(v) is int or v == 'eof' for v in stats.values()))

    def test_marker_with_extra_text_does_not_unlock_readiness(self):
        ready, stats = self.drain([b'private-prefix ==> OpenBao server started!\n'])
        self.assertFalse(ready.is_set())
        self.assertEqual(stats['marker_lines'], 0)
        self.assertEqual(stats['marker_extra_lines'], 1)
        self.assertNotIn('private-prefix', json.dumps(stats))

    def test_oversized_line_is_discarded_and_next_marker_detected(self):
        ready, stats = self.drain([b'x' * (runner._MAX_OUTPUT_LINE + 1), b'\n', runner._STARTED_LINE + b'\n'])
        self.assertTrue(ready.is_set())
        self.assertEqual(stats['oversized_lines'], 1)
        self.assertEqual(stats['complete_lines'], 2)
        self.assertEqual(stats['marker_lines'], 1)
        self.assertLess(len(json.dumps(stats)), 250)

    def test_reader_error_does_not_retain_exception_or_output(self):
        stats = runner._StartupDiagnostics()
        with patch.object(runner.selectors, 'DefaultSelector', side_effect=OSError('private-context')):
            runner._drain_server_output(io.BytesIO(b'private-server-output'), threading.Event(), threading.Event(), stats)
        self.assertEqual(stats.snapshot()['drain_state'], 'io_error')
        self.assertNotIn('private', json.dumps(stats.snapshot()))

    def test_stopped_reader_differs_from_eof(self):
        stop = threading.Event(); stop.set()
        read_fd, write_fd = os.pipe(); stats = runner._StartupDiagnostics()
        try:
            with os.fdopen(read_fd, 'rb', buffering=0) as output:
                runner._drain_server_output(output, threading.Event(), stop, stats)
        finally:
            os.close(write_fd)
        self.assertEqual(stats.snapshot()['drain_state'], 'stopped')

    def test_marker_timeout_keeps_code_and_does_not_contact_foreign_listener(self):
        class Process:
            _policy_delta_started = threading.Event()
            _policy_delta_startup_diagnostics = runner._StartupDiagnostics()
            def poll(self):
                return None
        with patch.object(runner, '_STARTUP_SECONDS', 0), patch.object(runner, '_request') as request:
            with self.assertRaises(runner.RunError) as caught:
                runner._wait_ready(Process(), 12345, 'private-root-token')
        self.assertEqual(str(caught.exception), 'startup_marker_timeout'); request.assert_not_called()
        details = caught.exception.startup_diagnostics
        self.assertEqual(details['health_checks'], 0); self.assertFalse(details['marker_seen'])
        self.assertIsNone(details['process_exit'])
        self.assertNotIn('private-root-token', json.dumps(details)); self.assertNotIn('12345', json.dumps(details))

    def test_cli_startup_failure_adds_optional_safe_evidence_and_no_report(self):
        error = runner.RunError('startup_marker_timeout', startup_diagnostics={'bytes_seen': 0, 'drain_state': 'eof'})
        captured = io.StringIO()
        with patch('policy_delta.suite.load_suite', return_value={}), patch('policy_delta.runner.run_suite', side_effect=error), patch('policy_delta.report.write_reports') as write, contextlib.redirect_stderr(captured):
            self.assertEqual(main(['not-read.json', '--bao', 'not-started', '--output', 'not-created-startup-report']), 2)
        lines = captured.getvalue().splitlines(); self.assertEqual(lines[0], 'PolicyDelta: startup_marker_timeout')
        self.assertEqual(json.loads(lines[1].split(': ', 1)[1]), error.startup_diagnostics); write.assert_not_called()

    def test_cli_other_failure_retains_existing_message(self):
        captured = io.StringIO()
        with patch('policy_delta.suite.load_suite', return_value={}), patch('policy_delta.runner.run_suite', side_effect=runner.RunError('admin_request_failed')), contextlib.redirect_stderr(captured):
            self.assertEqual(main(['not-read.json', '--bao', 'not-started', '--output', 'not-created-startup-report']), 2)
        self.assertEqual(captured.getvalue(), 'PolicyDelta: admin_request_failed\n')
