"""Reopen stored synthetic evidence; optionally rerun actual external OpenBao."""
from pathlib import Path
import json,hashlib,sys,os,tempfile,subprocess,argparse
from xml.etree import ElementTree as E
P=Path(__file__).resolve().parent
for name,h in json.loads((P/'MANIFEST.json').read_text()).items():
 if hashlib.sha256((P/name).read_bytes()).hexdigest()!=h:raise ValueError('Changed bundle member: '+name)
sys.path.insert(0,str(P/'runtime'))
from policy_delta.report import assess
reports={n:json.loads((P/n/'report.json').read_text())for n in['expansion','approved','unchanged','expectations-only','unavailable-runtime']}
for name,r in reports.items():
 assert assess(r)==r
 testcases=list(E.parse(P/name/'junit.xml').getroot().iter('testcase'));fail=sum(c.find('failure')is not None for c in testcases);errors=sum(c.find('error')is not None for c in testcases)
 expected=r['summary'];assert fail==expected['mismatches']if name=='expansion'else fail==expected['unapproved_expansions'];assert errors==expected['errors']+expected['run_errors']
selected=next(c for c in reports['expansion']['cases']if c['id']=='forbidden-parameter');assert selected['before']['status']==403 and selected['after']['status']==204 and selected['before']['capabilities']==selected['after']['capabilities']==['create','update']
for n in['approved','expectations-only']:
 for a,b in zip(reports['expansion']['cases'],reports[n]['cases']):assert a['before']==b['before']and a['after']==b['after']
assert[reports[n]['summary']['exit_code']for n in['expansion','expectations-only','approved','unchanged','unavailable-runtime']]==[1,1,0,0,2]
p=argparse.ArgumentParser();p.add_argument('--bao',type=Path);args=p.parse_args();live=False
if args.bao:
 with tempfile.TemporaryDirectory(prefix='policy-delta-bundle-live-')as td:
  env={**os.environ,'PYTHONPATH':str(P/'runtime'),'PYTHONDONTWRITEBYTECODE':'1'};q=subprocess.run([sys.executable,'-B','-m','policy_delta',str(P/'inputs/unchanged.json'),'--bao',str(args.bao),'--output',td+'/fresh'],env=env,capture_output=True,text=True,timeout=90);assert q.returncode==0,(q.stdout,q.stderr);fresh=json.loads(Path(td+'/fresh/report.json').read_text());assert fresh['cases']==reports['unchanged']['cases'];assert fresh['summary']==reports['unchanged']['summary'];live=True
print(json.dumps({'all_manifest_files_hash_exact':True,'stored_reports_reclassify_exactly':True,'JUnit_outcomes_match':True,'selected_request':[selected['before'],selected['after']],'verdicts':[1,1,0,0,2],'fresh_external_OpenBao_replay':live,'scope':'Synthetic finite observations, not complete policy safety or a signed origin'},indent=2))
