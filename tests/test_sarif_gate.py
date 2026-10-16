"""Regression tests for the fail-closed, component-aware CodeQL SARIF gate."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from check_sarif import failures

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'check_sarif.py'
GUID = '00000000-0000-4000-8000-000000000001'
OTHER_GUID = '00000000-0000-4000-8000-000000000002'


def rule(rule_id='py/redos', severity='7.5'):
    return {'id': rule_id, 'properties': {'tags': ['security'], 'security-severity': severity}}


def report(rules=None, results=None):
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'CodeQL', 'rules': rules if rules is not None else [rule()]}},
        'results': results if results is not None else [],
    }]}


def finding(**reference):
    return {'message': {'text': 'Synthetic finding'}, **reference}


def extension_report(severity='7.5'):
    data = report([rule('py/redos', '2.0')], [finding(
        ruleId='py/redos', ruleIndex=0,
        rule={'id': 'py/redos', 'index': 0, 'toolComponent': {'index': 0, 'name': 'python-queries'}},
    )])
    data['runs'][0]['tool']['extensions'] = [{'name': 'python-queries', 'guid': GUID,
                                             'rules': [rule(severity=severity)]}]
    return data


class SarifGateTests(unittest.TestCase):
    def assertBlocked(self, data, text=None):
        errors = failures(data)
        self.assertTrue(errors, data)
        if text:
            self.assertIn(text, '\n'.join(errors))
        return errors

    def test_completed_clean_report_passes(self):
        self.assertEqual(failures(report()), [])
        data = report([])
        data['runs'][0]['invocations'] = [{'executionSuccessful': True}]
        self.assertEqual(failures(data), [])

    def test_missing_optional_rules_and_invocations_pass_for_clean_results(self):
        data = report()
        del data['runs'][0]['tool']['driver']['rules']
        self.assertEqual(failures(data), [])

    def test_non_security_warning_and_error_results_pass(self):
        for level in ('note', 'warning', 'error'):
            with self.subTest(level=level):
                data = report([{'id': 'style', 'defaultConfiguration': {'level': level}}],
                              [finding(ruleId='style', level=level)])
                self.assertEqual(failures(data), [])

    def test_driver_high_critical_and_exact_threshold_fail(self):
        for severity in ('7', '7.0', '7.5', '9.0', '10.0', 7, 9.8):
            with self.subTest(severity=severity):
                self.assertBlocked(report([rule(severity=severity)], [finding(ruleId='py/redos')]),
                                   'high/critical')

    def test_driver_below_threshold_passes(self):
        for severity in ('0', '0.1', '4.0', '6.9', '6.99999999999999999999', 6.9):
            with self.subTest(severity=severity):
                self.assertEqual(failures(report([rule(severity=severity)],
                                                [finding(ruleId='py/redos')])), [])

    def test_extension_high_critical_fails_even_with_low_driver_rule(self):
        for severity in ('7.0', '9.5'):
            with self.subTest(severity=severity):
                self.assertBlocked(extension_report(severity), 'high/critical')

    def test_extension_low_does_not_inherit_high_driver_score(self):
        data = extension_report('3.0')
        data['runs'][0]['tool']['driver']['rules'][0]['properties']['security-severity'] = '9.0'
        self.assertEqual(failures(data), [])

    def test_rule_index_and_rule_reference_index_resolve(self):
        for reference in ({'ruleIndex': 0}, {'rule': {'index': 0}},
                          {'rule': {'id': 'py/redos'}}, {'ruleId': 'py/redos', 'ruleIndex': 0}):
            with self.subTest(reference=reference):
                self.assertBlocked(report(results=[finding(**reference)]), 'py/redos')

    def test_extension_index_is_local_to_the_selected_component(self):
        data = extension_report()
        data['runs'][0]['tool']['extensions'].insert(0, {'name': 'other', 'rules': [rule(severity='1.0')]})
        data['runs'][0]['results'][0]['rule']['toolComponent']['index'] = 1
        self.assertBlocked(data, 'high/critical')

    def test_extension_reference_without_rule_index_resolves_unique_id(self):
        data = extension_report()
        result = data['runs'][0]['results'][0]
        del result['ruleIndex']
        del result['rule']['index']
        self.assertBlocked(data, 'high/critical')

    def test_component_and_rule_guid_resolution(self):
        data = extension_report()
        result = data['runs'][0]['results'][0]
        result['rule'] = {'guid': OTHER_GUID, 'toolComponent': {'guid': GUID}}
        del result['ruleIndex']
        data['runs'][0]['tool']['extensions'][0]['rules'][0]['guid'] = OTHER_GUID
        self.assertBlocked(data, 'high/critical')

    def test_omitted_component_defaults_to_driver(self):
        data = extension_report()
        del data['runs'][0]['results'][0]['rule']['toolComponent']
        self.assertEqual(failures(data), [])
        data['runs'][0]['tool']['driver']['rules'] = []
        self.assertBlocked(data, 'Unresolved')

    def test_name_only_component_reference_cannot_select_extension(self):
        data = extension_report()
        data['runs'][0]['results'][0]['rule']['toolComponent'] = {'name': 'python-queries'}
        self.assertBlocked(data, 'does not match selected component')

    def test_unknown_and_ambiguous_rules_fail_closed(self):
        self.assertBlocked(report(results=[finding(ruleId='unknown')]), 'Unresolved')
        self.assertBlocked(report([rule(), rule(severity='1.0')], [finding(ruleId='py/redos')]),
                           'ambiguous')
        self.assertBlocked(report(results=[finding()]), 'no rule identifier')

    def test_duplicate_ids_are_safe_when_index_disambiguates(self):
        data = report([rule(), rule(severity='1.0')], [finding(ruleId='py/redos', ruleIndex=0)])
        self.assertBlocked(data, 'high/critical')
        data['runs'][0]['results'][0]['ruleIndex'] = 1
        self.assertEqual(failures(data), [])

    def test_conflicting_rule_identifiers_fail(self):
        variants = [
            {'ruleId': 'different', 'ruleIndex': 0},
            {'ruleId': 'py/redos', 'rule': {'id': 'different'}},
            {'ruleIndex': 0, 'rule': {'index': 1}},
            {'ruleIndex': 0, 'rule': {'guid': GUID}},
        ]
        for reference in variants:
            with self.subTest(reference=reference):
                self.assertBlocked(report(results=[finding(**reference)]), 'match' if 'guid' in reference.get('rule', {}) else None)

    def test_hierarchical_result_id_is_supported(self):
        for reference in ({'ruleId': 'py/redos/subkind', 'ruleIndex': 0},
                          {'ruleId': 'py/redos/subkind'}):
            self.assertBlocked(report(results=[finding(**reference)]), 'high/critical')

    def test_invalid_rule_and_component_indices_fail_closed(self):
        for index in (-1, -2, True, False, '0', 0.0, None, 100):
            for field in ('ruleIndex', 'index', 'component'):
                with self.subTest(index=index, field=field):
                    data = extension_report()
                    result = data['runs'][0]['results'][0]
                    if field == 'ruleIndex':
                        result['ruleIndex'] = index
                    elif field == 'index':
                        result['rule']['index'] = index
                    else:
                        result['rule']['toolComponent']['index'] = index
                    self.assertBlocked(data)

    def test_ambiguous_or_mismatched_component_guid_fails(self):
        data = extension_report()
        result = data['runs'][0]['results'][0]
        result['rule']['toolComponent'] = {'guid': GUID}
        data['runs'][0]['tool']['extensions'].append(copy.deepcopy(data['runs'][0]['tool']['extensions'][0]))
        self.assertBlocked(data, 'ambiguous toolComponent')
        result['rule']['toolComponent'] = {'index': 0, 'guid': OTHER_GUID}
        self.assertBlocked(data, 'does not match')
        result['rule']['toolComponent'] = {'guid': OTHER_GUID}
        self.assertBlocked(data, 'Unresolved')

    def test_ambiguous_rule_guid_fails(self):
        data = report([dict(rule(), guid=GUID), dict(rule('other'), guid=GUID)],
                      [finding(rule={'guid': GUID})])
        self.assertBlocked(data, 'ambiguous rule')

    def test_suppression_baseline_and_result_level_do_not_bypass_gate(self):
        data = report(results=[finding(ruleId='py/redos', level='none', baselineState='unchanged',
                                      suppressions=[{'kind': 'external', 'status': 'accepted'}])])
        self.assertBlocked(data, 'high/critical')

    def test_invalid_security_severity_fails_even_without_findings(self):
        values = (None, True, False, [], {}, '', 'high', 'NaN', 'Infinity', '-1', '10.1',
                  '1_0', ' 1.0 ', '1e-1', -1, 11, float('nan'), float('inf'), float('-inf'))
        for severity in values:
            with self.subTest(severity=severity):
                self.assertBlocked(report([rule(severity=severity)]), 'security-severity')

    def test_security_tag_without_score_fails_for_finding(self):
        data = report([{'id': 'py/security', 'properties': {'tags': ['security']}}],
                      [finding(ruleId='py/security')])
        self.assertBlocked(data, 'no security-severity')

    def test_missing_or_null_results_do_not_mean_clean_analysis(self):
        data = report()
        del data['runs'][0]['results']
        self.assertBlocked(data, 'missing/null')
        data['runs'][0]['results'] = None
        self.assertBlocked(data, 'missing/null')

    def test_failed_or_unconfirmed_invocation_fails(self):
        for invocation in ({}, {'executionSuccessful': False}, {'executionSuccessful': 'true'},
                           {'executionSuccessful': 1}, {'executionSuccessful': None}):
            data = report()
            data['runs'][0]['invocations'] = [invocation]
            self.assertBlocked(data, 'Analysis failed or success unconfirmed')

    def test_successful_invocation_can_have_nonzero_exit_code(self):
        data = report()
        data['runs'][0]['invocations'] = [{'executionSuccessful': True, 'exitCode': 1}]
        self.assertEqual(failures(data), [])

    def test_process_start_failure_and_interruption_fail(self):
        for key, value in (('processStartFailureMessage', 'failed'), ('exitSignalName', 'SIGTERM'),
                           ('exitSignalNumber', 15)):
            data = report()
            data['runs'][0]['invocations'] = [{'executionSuccessful': True, key: value}]
            self.assertBlocked(data, 'failed to start or was interrupted')

    def test_analysis_error_notifications_fail_but_warnings_pass(self):
        for key in ('toolExecutionNotifications', 'toolConfigurationNotifications'):
            data = report()
            notification = {'level': 'error', 'message': {'text': 'Partial analysis'}}
            data['runs'][0]['invocations'] = [{'executionSuccessful': True, key: [notification]}]
            self.assertBlocked(data, 'Analysis error')
            notification['level'] = 'warning'
            self.assertEqual(failures(data), [])
            del notification['level']
            self.assertEqual(failures(data), [])

    def test_externalized_data_is_rejected(self):
        data = report()
        data['inlineExternalProperties'] = [{'results': []}]
        self.assertBlocked(data, 'Externalized')
        del data['inlineExternalProperties']
        data['runs'][0]['externalPropertyFileReferences'] = {'results': [{'location': {'uri': 'elsewhere'}}]}
        self.assertBlocked(data, 'Externalized')

    def test_malformed_top_level_data_is_rejected(self):
        for data in (None, [], '', {}, {'runs': []}, {'version': '2.0', 'runs': []},
                     {'version': '2.1.0', 'runs': None}, {'version': '2.1.0', 'runs': {}},
                     {'version': '2.1.0', 'runs': []}, {'version': '2.1.0', 'runs': [None]}):
            with self.subTest(data=data):
                self.assertBlocked(data)

    def test_malformed_relevant_objects_are_rejected(self):
        edits = [
            (('tool',), None), (('tool', 'driver'), []), (('tool', 'driver', 'name'), None),
            (('tool', 'extensions'), {}), (('tool', 'extensions'), [None]),
            (('tool', 'driver', 'rules'), {}), (('tool', 'driver', 'rules'), [None]),
            (('results',), {}), (('results',), [None]),
            (('results',), [finding(rule=None)]), (('results',), [finding(ruleId=12)]),
            (('results',), [finding(rule={'toolComponent': None})]),
            (('invocations',), None), (('invocations',), [None]),
            (('invocations',), [{'executionSuccessful': True, 'toolExecutionNotifications': {}}]),
            (('invocations',), [{'executionSuccessful': True, 'toolExecutionNotifications': [None]}]),
            (('invocations',), [{'executionSuccessful': True, 'toolExecutionNotifications': [{'level': []}]}]),
        ]
        for path, value in edits:
            with self.subTest(path=path, value=value):
                data = report()
                target = data['runs'][0]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assertBlocked(data)
        for value in (None, [], 'security'):
            self.assertBlocked(report([{'id': 'x', 'properties': value}]))
        for value in (None, {}, 'security'):
            self.assertBlocked(report([{'id': 'x', 'properties': {'tags': value}}]))
        self.assertBlocked(report([{'properties': {}}]))
        self.assertBlocked(report([{'id': 'x', 'properties': {'tags': [None]}}]))

    def test_all_runs_and_results_are_checked(self):
        data = report()
        data['runs'].extend([report(results=[finding(ruleId='missing')])['runs'][0],
                             report(results=[finding(ruleId='py/redos')])['runs'][0]])
        errors = self.assertBlocked(data)
        self.assertEqual(len(errors), 2)
        self.assertIn('run 1', errors[0])
        self.assertIn('run 2', errors[1])


class SarifCliTests(unittest.TestCase):
    def run_gate(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                              capture_output=True, text=True, timeout=5)

    def test_clean_file_and_recursive_directory_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'nested' / 'python.sarif'
            path.parent.mkdir()
            path.write_text(json.dumps(report()))
            self.assertEqual(self.run_gate(temp).returncode, 0)
            self.assertEqual(self.run_gate(path).returncode, 0)

    def test_missing_path_no_files_and_bad_arguments_fail(self):
        self.assertNotEqual(self.run_gate().returncode, 0)
        with tempfile.TemporaryDirectory() as temp:
            for path in (Path(temp), Path(temp) / 'missing'):
                result = self.run_gate(path)
                self.assertEqual(result.returncode, 1)
                self.assertIn('did not produce SARIF', result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_high_finding_is_nonzero_and_identified(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'python.sarif').write_text(json.dumps(extension_report()))
            result = self.run_gate(temp)
            self.assertEqual(result.returncode, 1)
            self.assertIn('py/redos', result.stderr)
            self.assertIn('python.sarif', result.stderr)

    def test_bad_json_encoding_duplicates_and_constants_fail_with_diagnostic(self):
        bad_reports = (b'{', b'\xff', b'{"version":"2.1.0","runs":[],"runs":[]}',
                       b'{"version":"2.1.0","extra":NaN,"runs":[]}',
                       b'{"version":"2.1.0","extra":Infinity,"runs":[]}')
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'invalid.sarif'
            for content in bad_reports:
                with self.subTest(content=content):
                    path.write_bytes(content)
                    result = self.run_gate(temp)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('Cannot read/parse SARIF', result.stderr)
                    self.assertNotIn('Traceback', result.stderr)

    def test_all_files_are_checked_after_parse_error(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'a-clean.sarif').write_text(json.dumps(report()))
            (Path(temp) / 'b-invalid.sarif').write_text('{')
            (Path(temp) / 'c-high.sarif').write_text(json.dumps(extension_report()))
            result = self.run_gate(temp)
            self.assertEqual(result.returncode, 1)
            self.assertIn('b-invalid.sarif', result.stderr)
            self.assertIn('c-high.sarif', result.stderr)


if __name__ == '__main__':
    unittest.main()
