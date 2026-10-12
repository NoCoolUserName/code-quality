import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from dependency_gate import (Blocked, version_change, manifest_change, npm_lock_change,
                             requirements_change, changes_allowed, identity_allowed,
                             checks_allowed, protections_allowed)


class GateTests(unittest.TestCase):
    def test_patch_allowed(self):
        version_change('1.2.3', '1.2.4')

    def test_nonpatch_denied(self):
        for old, new in [('1.2.3','2.0.0'),('1.2.3','1.3.0'),('1.2.3','1.2.2'),('1.2.3','1.2.3'),('1.2.3','1.2.4-rc.1')]:
            with self.subTest(new=new), self.assertRaises(Blocked):
                version_change(old,new)

    def test_opt_in_dev_minor(self):
        a={'devDependencies':{'vitest':'^4.1.0'}}
        b={'devDependencies':{'vitest':'^4.2.0'}}
        self.assertEqual(manifest_change(a,b,True),1)
        with self.assertRaises(Blocked): manifest_change(a,b)
        with self.assertRaises(Blocked): manifest_change({'dependencies':a['devDependencies']},{'dependencies':b['devDependencies']},True)

    def test_manifest_script_injection_denied(self):
        with self.assertRaises(Blocked):
            manifest_change({'dependencies':{'x':'1.2.3'}},{'dependencies':{'x':'1.2.4'},'scripts':{'postinstall':'touch /tmp/bad'}})

    def test_range_source_and_additions_denied(self):
        for dep in ({'x':'~1.2.4'},{'x':'https://example.com/x'},{'x':'1.2.4','y':'1.0.0'}):
            with self.assertRaises(Blocked): manifest_change({'dependencies':{'x':'^1.2.3'}},{'dependencies':dep})

    def test_exact_requirements_only(self):
        self.assertEqual(requirements_change('pydantic==2.13.5\n','pydantic==2.13.6\n'),1)
        for new in ['pydantic==2.14.0\n','-e https://example.com/x\n','pydantic==2.13.6\nnew==1.0.0\n']:
            with self.assertRaises(Blocked): requirements_change('pydantic==2.13.5\n',new)

    def test_real_pydantic_core_conflict_not_patch(self):
        with self.assertRaises(Blocked): requirements_change('pydantic_core==2.46.5','pydantic_core==2.49.0')

    def lock(self,version):
        return {'lockfileVersion':3,'packages':{'':{'name':'example'},'node_modules/x':{'version':version,'resolved':'https://registry.npmjs.org/x/-/x-'+version+'.tgz','integrity':'sha512-YWJjZA=='}}}

    def test_npm_patch_and_metadata(self):
        a,b=self.lock('1.2.3'),self.lock('1.2.4')
        self.assertEqual(npm_lock_change(a,b),1)
        for field,value in [('resolved','https://evil.example/x.tgz'),('integrity',''),('hasInstallScript',True),('link',True)]:
            c=copy.deepcopy(b); c['packages']['node_modules/x'][field]=value
            with self.subTest(field=field),self.assertRaises(Blocked): npm_lock_change(a,c)

    def test_transitive_major_blocks(self):
        with self.assertRaises(Blocked): npm_lock_change(self.lock('1.2.3'),self.lock('2.0.0'))

    def test_workflow_or_security_policy_changes_block(self):
        for path in ['.github/workflows/ci.yml','.github/dependency-policy.json','src/app.ts','SECURITY.md']:
            with self.assertRaises(Blocked): changes_allowed([{'filename':path,'status':'modified'}],{path:('a','b')},{'dependency_files':['package-lock.json']})

    def test_renames_block(self):
        with self.assertRaises(Blocked): changes_allowed([{'filename':'requirements.txt','status':'renamed'}],{}, {'dependency_files':['requirements.txt']})

    def test_identity_and_fork(self):
        pr={'state':'open','user':{'login':'dependabot[bot]','id':49699333},'head':{'repo':{'full_name':'o/r'}},'base':{'repo':{'full_name':'o/r'},'ref':'main'}}
        identity_allowed(pr,'o/r')
        pr['head']['repo']['full_name']='evil/r'
        with self.assertRaises(Blocked): identity_allowed(pr,'o/r')

    def fixture(self):
        policy={'required_workflows':['.github/workflows/code-quality.yml','.github/workflows/ci.yml'],'required_checks':['quality','test (3.12)','test (3.13)']}
        runs=[{'id':i,'path':p,'event':'pull_request','status':'completed','conclusion':'success'} for i,p in enumerate(policy['required_workflows'])]
        checks=[{'id':i,'name':n,'app':{'id':15368},'status':'completed','conclusion':'success'} for i,n in enumerate(policy['required_checks'])]
        return policy,runs,checks

    def test_all_project_checks_required(self):
        p,r,c=self.fixture(); checks_allowed(p,r,c)
        for conclusion in ['failure','cancelled','skipped','neutral',None]:
            bad=copy.deepcopy(c);bad[-1]['conclusion']=conclusion
            with self.subTest(conclusion=conclusion),self.assertRaises(Blocked): checks_allowed(p,r,bad)
        with self.assertRaises(Blocked): checks_allowed(p,r,c[:-1])
        with self.assertRaises(Blocked): checks_allowed(p,r[:-1],c)

    def test_newer_failed_run_blocks_old_success(self):
        p,r,c=self.fixture();r.append(dict(r[-1],id=99,conclusion='failure'))
        with self.assertRaises(Blocked): checks_allowed(p,r,c)

    def test_check_spoof_and_pending_block(self):
        p,r,c=self.fixture();c[-1]['app']['id']=1
        with self.assertRaises(Blocked): checks_allowed(p,r,c)
        p,r,c=self.fixture();c.append({'id':99,'name':'additional','app':{'id':15368},'status':'in_progress','conclusion':None})
        with self.assertRaises(Blocked): checks_allowed(p,r,c)

    def test_native_rules_required(self):
        p,_,_=self.fixture()
        with self.assertRaises(Blocked): protections_allowed(p,[])
        rules=[{'type':'pull_request'},{'type':'required_status_checks','parameters':{'strict_required_status_checks_policy':True,'required_status_checks':[{'context':n,'integration_id':15368} for n in p['required_checks']]}}]
        protections_allowed(p,rules)
        rules[-1]['parameters']['strict_required_status_checks_policy']=False
        with self.assertRaises(Blocked): protections_allowed(p,rules)


class SarifTests(unittest.TestCase):
    def test_clean_and_high_severity(self):
        from check_sarif import failures
        self.assertEqual(failures({'runs':[{'results':[]}]}),[])
        self.assertTrue(failures({'runs':[]}))
        self.assertTrue(failures({'runs':[{'invocations':[{'executionSuccessful':False}]}]}))
        self.assertTrue(failures({'runs':[{'tool':{'driver':{'rules':[{'id':'x','properties':{'security-severity':'8.1'}}]}},'results':[{'ruleId':'x'}]}]}))

if __name__=='__main__': unittest.main()
