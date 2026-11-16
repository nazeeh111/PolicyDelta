"""Owned synthetic child cleanup, interruption and incomplete-report controls."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from policy_delta import runner
from policy_delta.__main__ import main
from test_runner import suite


class CleanupInterruptTests(unittest.TestCase):
    def spawn(self):
        process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(self.reap, process)
        return process

    @staticmethod
    def reap(process):
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)

    def test_single_interrupt_terminate_and_wait_reap_real_owned_child(self):
        for method in ('terminate','wait'):
            with self.subTest(method=method):
                child=self.spawn(); original=getattr(child,method); count=[0]
                def inject(*args,**kwargs):
                    count[0]+=1
                    if count[0]==1: raise KeyboardInterrupt('synthetic secret')
                    return original(*args,**kwargs)
                with patch.object(child,method,side_effect=inject):
                    with self.assertRaises(KeyboardInterrupt):runner._stop_server(child)
                self.assertIsNotNone(child.poll());self.assertGreaterEqual(count[0],2)

    def test_repeated_interrupt_escalates_and_reports_interrupt(self):
        child=self.spawn()
        with patch.object(child,'terminate',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):runner._stop_server(child)
        self.assertIsNotNone(child.poll())

    def test_permission_denial_does_not_try_kill(self):
        child=self.spawn()
        with patch.object(child,'terminate',side_effect=PermissionError('synthetic secret')), patch.object(child,'kill',wraps=child.kill) as kill:
            with self.assertRaisesRegex(runner.RunError,'shutdown_failed'):runner._stop_server(child)
            kill.assert_not_called()

    def test_cli_preserves_complete_before_and_not_run_after_then_safe_retry(self):
        fixture=Path(__file__).resolve().parents[1]/'examples/unchanged.json'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); child=self.spawn(); terminate=child.terminate; count=[0]
            def interrupted(*a,**kw):
                count[0]+=1
                if count[0]==1:raise KeyboardInterrupt('synthetic-private-marker')
                return terminate(*a,**kw)
            with patch.object(child,'terminate',side_effect=interrupted), \
                 patch.object(runner,'_check_version',return_value='OpenBao 2.7.0'), \
                 patch.object(runner,'_free_port',return_value=12345), \
                 patch.object(runner,'_start_server',return_value=child), \
                 patch.object(runner,'_wait_ready'),patch.object(runner,'_admin'), \
                 patch.object(runner,'_run_case',return_value={'status':403,'decision':'deny','capabilities':[]}), \
                 contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                code=main([str(fixture),'--bao',str(root/'fake'),'--output',str(root/'report')])
            self.assertEqual(code,2);self.assertIsNotNone(child.poll())
            report=json.loads((root/'report/report.json').read_text())
            self.assertTrue(all(x['before']['decision']=='deny' and x['before']['status']==403 and x['after']['decision']=='not_run' for x in report['cases']))
            self.assertEqual(report['execution']['failures'][0]['code'],'interrupted')
            self.assertEqual(report['execution']['failures'][0]['stage'],'shutdown')
            for path in (root/'report').iterdir():self.assertNotIn('synthetic-private-marker',path.read_text())
            with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(fixture),'--bao',str(root/'missing'),'--output',str(root/'retry')]),2)
            self.assertEqual(json.loads((root/'retry/report.json').read_text())['execution']['failures'][0]['stage'],'engine_version')

    def test_real_cli_synthetic_start_failure_and_retry(self):
        fixture=Path(__file__).resolve().parents[1]/'examples/unchanged.json'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); stub=root/'fake-bao'
            stub.write_text('#!'+sys.executable+'\nimport sys\nif sys.argv[1:] == ["version"]: print("OpenBao v2.7.0")\nelse: print("synthetic-private-marker", flush=True); sys.exit(3)\n')
            stub.chmod(0o700)
            outputs=[]
            for name in ('one','retry'):
                out=root/name
                proc=subprocess.run([sys.executable,'-m','policy_delta',str(fixture),'--bao',str(stub),'--output',str(out)],capture_output=True,text=True,timeout=25)
                self.assertEqual(proc.returncode,2,proc.stderr)
                report=json.loads((out/'report.json').read_text());outputs.append(report)
                self.assertEqual(report['execution']['status'],'incomplete')
                self.assertTrue(all(case[v]['decision']=='not_run' for case in report['cases'] for v in ('before','after')))
                for f in out.iterdir():self.assertNotIn('synthetic-private-marker',f.read_text())
                self.assertNotIn('synthetic-private-marker',proc.stdout+proc.stderr)
            self.assertEqual(outputs[0]['execution']['failures'][0]['stage'],'startup')
            self.assertEqual(outputs[1]['execution']['failures'][0]['stage'],'startup')

    def test_interrupt_then_timeout_escalates_and_retains_interrupt(self):
        child=self.spawn(); real_wait=child.wait; calls=[0]
        def wait(*a,**kw):
            calls[0]+=1
            if calls[0]==1: raise KeyboardInterrupt
            if calls[0]==2: raise subprocess.TimeoutExpired('synthetic',1)
            return real_wait(*a,**kw)
        with patch.object(child,'wait',side_effect=wait),patch.object(child,'kill',wraps=child.kill) as kill:
            with self.assertRaises(KeyboardInterrupt):runner._stop_server(child)
            kill.assert_called_once()
        self.assertIsNotNone(child.poll())

    def test_interruption_and_shutdown_failure_are_both_recorded(self):
        child=self.spawn()
        with patch.object(child,'terminate',side_effect=[KeyboardInterrupt, PermissionError('secret')]), \
             patch.object(runner,'_check_version',return_value='OpenBao 2.7.0'), \
             patch.object(runner,'_free_port',return_value=12345), \
             patch.object(runner,'_start_server',return_value=child), \
             patch.object(runner,'_wait_ready'),patch.object(runner,'_admin'), \
             patch.object(runner,'_run_case',return_value={'status':403,'decision':'deny','capabilities':[]}):
            report=runner.run_suite(suite(),Path('/synthetic'))
        self.assertEqual([x['code'] for x in report['execution']['failures']],['interrupted','shutdown_failed'])
        self.assertNotIn('secret',json.dumps(report))

    def test_start_failure_with_cleanup_outcomes_preserves_both_and_owned_pid(self):
        from policy_delta.report import assess, render_html, render_junit
        for mode in ('success','error','interrupt','denial'):
            with self.subTest(mode=mode):
                child=self.spawn(); real_stop=runner._stop_server
                def stop(proc):
                    if mode=='denial':
                        with patch.object(proc,'terminate',side_effect=PermissionError('private-denial')):
                            return real_stop(proc)
                    real_stop(proc)
                    if mode=='error':raise runner.RunError('shutdown_failed')
                    if mode=='interrupt':raise KeyboardInterrupt('private-interrupt')
                with patch.object(runner,'_check_version',return_value='OpenBao 2.7.0'), \
                     patch.object(runner,'_free_port',return_value=12345), \
                     patch.object(runner.subprocess,'Popen',return_value=child), \
                     patch.object(runner.threading.Thread,'start',side_effect=RuntimeError('private-start')), \
                     patch.object(runner,'_stop_server',side_effect=stop):
                    report=runner.run_suite(suite(),Path('/synthetic'))
                failures=report['execution']['failures']
                self.assertEqual(failures[0],{'stage':'server_start','variant':'before','code':'server_start_failed'})
                self.assertTrue(all(c[v]['decision']=='not_run' for c in report['cases'] for v in ('before','after')))
                if mode=='success':self.assertEqual(len(failures),1)
                else:
                    self.assertEqual(len(failures),2)
                    self.assertEqual(failures[1]['stage'],'shutdown')
                    self.assertEqual(failures[1]['code'],'interrupted' if mode=='interrupt' else 'shutdown_failed')
                    if mode=='denial':self.assertEqual(failures[1]['reason'],'permission_denied')
                    self.assertEqual(failures[1]['owned_process']['pid'],child.pid)
                    self.assertEqual(failures[1]['owned_process']['status_at_cleanup'],'running' if mode=='denial' else 'exited')
                checked=assess(report);self.assertEqual(checked['summary']['exit_code'],2)
                text=json.dumps(checked)+render_html(checked)+render_junit(checked)
                self.assertNotIn('private-',text)
                if mode=='denial':
                    self.assertIsNone(child.poll())
                    self.assertIn('PID may be reused',render_html(checked))
                    self.assertIn(str(child.pid),render_junit(checked))
                else:self.assertIsNotNone(child.poll())

    def test_cli_dual_failure_serializes_actionable_sanitized_ownership(self):
        fixture=Path(__file__).resolve().parents[1]/'examples/unchanged.json'
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'report';child=self.spawn()
            with patch.object(runner,'_check_version',return_value='OpenBao 2.7.0'), \
                 patch.object(runner,'_free_port',return_value=12345), \
                 patch.object(runner.subprocess,'Popen',return_value=child), \
                 patch.object(runner.threading.Thread,'start',side_effect=RuntimeError('private-start')), \
                 patch.object(child,'terminate',side_effect=PermissionError('private-denial')), \
                 contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                code=main([str(fixture),'--bao',str(Path(directory)/'fake'),'--output',str(out)])
            self.assertEqual(code,2);self.assertIsNone(child.poll())
            report=json.loads((out/'report.json').read_text());failures=report['execution']['failures']
            self.assertEqual([(f['stage'],f['code']) for f in failures],[('server_start','server_start_failed'),('shutdown','shutdown_failed')])
            self.assertEqual(failures[1]['reason'],'permission_denied')
            self.assertEqual(failures[1]['owned_process'],{'pid':child.pid,'status_at_cleanup':'running'})
            for path in out.iterdir():self.assertNotIn('private-',path.read_text())
            self.assertIn('PID may be reused',(out/'index.html').read_text())
