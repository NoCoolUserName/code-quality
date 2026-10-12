"""One-time admin setup; adds our rules without replacing unrelated protections.
Run with GH_TOKEN from an authenticated administrator session, never from PR CI.
"""
import argparse
import json
import os
from dependency_gate import GitHub, ACTIONS_ID, require

parser=argparse.ArgumentParser()
parser.add_argument('repository')
parser.add_argument('--apply',action='store_true')
args=parser.parse_args()
api=GitHub(args.repository,os.environ['GH_TOKEN'])
policy=json.loads(api.file('.github/dependency-policy.json','main'))
require(bool(policy['required_checks']),'Missing required checks')
body={
    'name':'code-quality-required-checks', 'target':'branch','enforcement':'active',
    'bypass_actors':[],
    'conditions':{'ref_name':{'include':['refs/heads/main'],'exclude':[]}},
    'rules':[
        {'type':'deletion'}, {'type':'non_fast_forward'},
        {'type':'pull_request','parameters':{
            'required_approving_review_count':0, 'dismiss_stale_reviews_on_push':False,
            'require_code_owner_review':False,'require_last_push_approval':False,
            'required_review_thread_resolution':True}},
        {'type':'required_status_checks','parameters':{
            'strict_required_status_checks_policy':True,
            'do_not_enforce_on_create':False,
            'required_status_checks':[{'context':x,'integration_id':ACTIONS_ID} for x in policy['required_checks']]}}
    ]}
existing=[x for x in api.pages('/rulesets') if x['name']==body['name']]
require(len(existing)<=1,'Ambiguous existing rulesets')
print(json.dumps(body,indent=2))
if args.apply:
    path='/rulesets'+('/'+str(existing[0]['id']) if existing else '')
    result=api.call(path,'PUT' if existing else 'POST',body)
    print('Applied ruleset', result['id'])
else:
    print('Preview only. Use --apply from an admin-authenticated session.')
