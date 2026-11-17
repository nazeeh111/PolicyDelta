"""Source-bound observed-request comparison, not an internal policy-rule trace."""
from pathlib import Path
import json,html
P=Path(__file__).resolve().parent;reports={n:json.loads((P/n/'report.json').read_text())for n in['expansion','approved','expectations-only']};row=next(c for c in reports['expansion']['cases']if c['id']=='forbidden-parameter');assert row['before']=={'status':403,'decision':'deny','capabilities':['create','update']};assert row['after']=={'status':204,'decision':'allow','capabilities':['create','update']};before=(P/'inputs/policies/before.hcl').read_text();after=(P/'inputs/policies/after.hcl').read_text();assert'"stage" = ["test"]'in before and'required_parameters'in before and'required_parameters'not in after
assert reports['expansion']['summary']['exit_code']==reports['expectations-only']['summary']['exit_code']==1 and reports['approved']['summary']['exit_code']==0

def T(x,y,s,z=16,c='#202724',mono=False):return f'<text x="{x}" y="{y}" font-family="{("Courier New, Courier, monospace"if mono else"Arial, Helvetica, sans-serif")}" font-size="{z}" fill="{c}">{html.escape(s)}</text>'
def render(phone):
 W=375 if phone else 1280;H=1160 if phone else 720;slug='request-mobile'if phone else'request';a=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-labelledby="{slug}-title {slug}-desc"><title id="{slug}-title">Same capability, newly allowed request</title><desc id="{slug}-desc">A synthetic POST to legacy/release is denied with HTTP 403 before and allowed with HTTP 204 after removing parameter restrictions, while both capability probes return create and update; matching expectations alone does not approve the expansion.</desc><rect width="100%" height="100%" fill="#f5f4ee"/>',T(24,36,'PolicyDelta / REQUEST-LEVEL EVIDENCE',13,'#174c67')]
 if phone:a +=[T(24,80,'Same capability.',30),T(24,120,'Newly allowed request.',28)]
 else:a +=[T(40,100,'Same capability. Newly allowed request.',43)]
 rqy=160 if phone else 140;a +=[T(24 if phone else 40,rqy,'ONE SYNTHETIC REQUEST · forbidden-parameter',12,'#59635d'),T(24 if phone else 40,rqy+34,'POST legacy/release',20,'#174c67',True),T(24 if phone else 40,rqy+64,'stage = "prod"',17,'#202724',True)]
 for i in range(2):
  x=20 if phone else 40+i*624;y=272+i*288 if phone else 260;w=335 if phone else 600;h=260;a.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#fffefa" stroke="#a6b3aa"/>');a.append(T(x+16,y+30,'BEFORE POLICY'if i==0 else'AFTER POLICY',13,'#59635d'))
  if i==0:a +=[T(x+16,y+65,'Stage restricted to "test"',20),T(x+16,y+94,'Required stage + allowed_parameters',13,'#59635d')]
  else:a +=[T(x+16,y+65,'Parameter restrictions removed',18 if phone else 22),T(x+16,y+94,'Same path and create/update grant',13,'#59635d')]
  a +=[T(x+16,y+132,'Capability probe',13,'#59635d'),T(x+16,y+158,'create, update',19,'#174c67',True),T(x+16,y+207,'HTTP 403 · DENY'if i==0 else'HTTP 204 · ALLOW',26,'#7c3f24'if i==0 else'#216846'),T(x+16,y+239,'Actual OpenBao 2.7.0 observation',12,'#59635d')]
 by=904 if phone else 568
 if phone:
  a +=[T(24,by,'Approval changes the suite verdict,',18),T(24,by+28,'not the observed access expansion.',18),T(24,by+69,'Unapproved → exit 1',18,'#7c3f24'),T(24,by+103,'Expect allow alone → exit 1',18,'#7c3f24'),T(24,by+137,'Expect allow + approve → exit 0',18,'#216846'),T(24,by+190,'Full suite: 11 cases, 4 expansions.',13,'#59635d'),T(24,by+218,'Finite synthetic regression, not policy proof.',13,'#59635d')]
 else:a +=[T(40,by,'OBSERVATIONS RETAINED / THREE REVIEW CONFIGURATIONS',13,'#59635d'),T(40,by+40,'Unapproved: exit 1',22,'#7c3f24'),T(440,by+40,'Expect allow alone: exit 1',22,'#7c3f24'),T(876,by+40,'Expect + approve: exit 0',22,'#216846'),T(40,by+82,'The full suite has 11 cases and 4 expansions; 2 keep identical capability lists. Approval is explicit per named case.',17,'#59635d'),T(40,by+118,'Synthetic local observations. This is not an internal authorization trace or a proof of complete policy safety.',15,'#59635d')]
 a.append('</svg>');svg=''.join(a);doc='<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PolicyDelta request evidence</title><style>body{margin:0;background:#f5f4ee}svg{display:block;width:100%;height:auto}</style><main>'+svg+'</main></html>';return doc,svg
for phone in[False,True]:
 doc,svg=render(phone);name='request-mobile'if phone else'request';(P/(name+'.html')).write_text(doc);(P/(name+'.svg')).write_text(svg)
