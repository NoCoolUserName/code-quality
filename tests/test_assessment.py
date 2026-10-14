"""Exercise the complete gate, including races and merge writes, without credentials."""
import copy
import json
import unittest
import test_dependency_gate
from dependency_gate import assess, Blocked


class API:
    def __init__(self):
        self.policy, self.runs, self.checks = test_dependency_gate.GateTests().fixture()
        self.policy.update(enabled=True, dependency_files=['requirements.txt'])
        self.pr = {'state':'open','user':{'id':49699333,'login':'dependabot[bot]'},
                   'head':{'sha':'new','repo':{'full_name':'o/r'}},
                   'base':{'sha':'base','ref':'main','repo':{'full_name':'o/r'}},
                   'changed_files':1,'mergeable':True,'mergeable_state':'clean'}
        self.rules=[{'type':'pull_request'},{'type':'required_status_checks','parameters':{'strict_required_status_checks_policy':True,'required_status_checks':[{'context':n,'integration_id':15368} for n in self.policy['required_checks']]}}]
        self.branch='base'; self.writes=[]; self.versions={'base':'x==1.2.3','new':'x==1.2.4'}
        self.author={'id':49699333}; self.refreshes=0; self.move_head=False
    def call(self,path,method='GET',data=None):
        if method!='GET':
            self.writes.append((path,method,data));return {'merged':True,'sha':'merged'}
        if path=='/pulls/1':
            self.refreshes+=1
            pr=copy.deepcopy(self.pr)
            if self.move_head and self.refreshes>1: pr['head']['sha']='moved'
            return pr
        if path.endswith('/status'): return {'statuses':[],'state':'pending'}
        if path=='/rules/branches/main':return self.rules
        if path=='/branches/main':return {'commit':{'sha':self.branch}}
        raise AssertionError(path)
    def pages(self,path,key=None):
        if path.endswith('/commits'):return [{'author':self.author}]
        if path.endswith('/files'):return [{'filename':'requirements.txt','status':'modified'}]
        if path.startswith('/actions/runs?'):return self.runs
        if path.endswith('/check-runs'):return self.checks
        raise AssertionError(path)
    def file(self,path,ref):
        if path=='.github/dependency-policy.json':return json.dumps(self.policy)
        return self.versions[ref]


class AssessmentTests(unittest.TestCase):
    def test_eligible_dry_run_cannot_write(self):
        api=API();self.assertIn('ELIGIBLE',assess(api,'o/r',1));self.assertEqual(api.writes,[])
    def test_eligible_merge_pins_expected_head(self):
        api=API();self.assertEqual(assess(api,'o/r',1,True),'MERGED merged')
        self.assertEqual(api.writes,[('/pulls/1/merge','PUT',{'sha':'new','merge_method':'squash'})])
    def test_failure_scenarios_never_write(self):
        for case in ['core-failed','native-missing','behind','head-moved','major','non-bot','unknown-author','policy-off']:
            with self.subTest(case=case):
                api=API()
                if case=='core-failed':api.checks[-1]['conclusion']='failure'
                if case=='native-missing':api.rules=[]
                if case=='behind':api.branch='changed'
                if case=='head-moved':api.move_head=True
                if case=='major':api.versions['new']='x==2.0.0'
                if case=='non-bot':api.author={'id':1}
                if case=='unknown-author':api.author=None
                if case=='policy-off':api.policy['enabled']=False
                with self.assertRaises(Blocked):assess(api,'o/r',1,True)
                self.assertEqual(api.writes,[])
