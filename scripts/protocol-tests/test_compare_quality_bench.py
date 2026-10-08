import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('comparison', Path(__file__).with_name('compare-quality-bench.py'))
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class ComparisonEvidenceTests(unittest.TestCase):
    def test_both_empty_oracles_do_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def run(command, **kw):
                kw['stdout'].write('BenchmarkT06Pipeline/case 1 100 ns/op\n')
                Path(kw['env']['YAK_T06_BENCH_EVIDENCE']).write_text('')
                return type('Result', (), {'returncode': 0})()
            with patch.object(comparison, 'fingerprints', return_value={}), \
                 patch.object(comparison, 'git_state', return_value={}, create=True), \
                 patch.object(comparison.subprocess, 'check_output', return_value='test\n'), \
                 patch.object(comparison.subprocess, 'run', side_effect=run), \
                 patch.object(comparison.platform, 'system', return_value='Linux'), \
                 patch.object(comparison.platform, 'platform', return_value='test'), \
                 patch('sys.argv', ['compare', str(root), str(root), '--output', str(root/'out'), '--base-sha', 'test', '--head-sha', 'test']):
                with self.assertRaises((SystemExit, ValueError)):
                    comparison.main()
            result = root/'out'/'environment.json'
            if result.exists():
                self.assertFalse(json.loads(result.read_text()).get('complete', False))

    def complete(self):
        evidence={};rows={}
        for name in comparison.inventory():
            bench,cpu=name.rsplit('/procs',1)
            metrics={'ns/op':100,'B/op':1,'allocs/op':1,'gomaxprocs':int(cpu),'capture-bytes/batch':100}
            reader=name.startswith('BenchmarkT06CaptureReader/')
            if reader:
                metrics['records/batch']=1
                result=dict(Records=1,Bytes=20,Digest='a'*64)
            else:
                metrics.update({k:1 for k in ['cpu-ns/batch','p50-ns/batch','p95-ns/batch','p99-ns/batch','heap-bytes','rss-bytes','peak-buffer-bytes','semantic-msg/batch','semantic-bytes/batch']})
                metrics.update({k:0 for k in ['unknown/batch','limited-bytes/batch','rejected/batch']})
                result=dict(Messages=1,Bytes=20,Opaque=0,Unknown=0,Limited=0,Drops=0,Envelopes=0,Digest='a'*64,FieldDigest='b'*64,OrderedDigest='c'*64)
            rows[bench+('' if cpu=='1' else '-'+cpu)]=metrics
            evidence[name]={'result':result,'gomaxprocs':int(cpu),'iterations':100,'raw_profile_sha256':'d'*64}
        return rows,evidence

    def test_complete_inventory_passes(self):
        rows,evidence=self.complete()
        comparison.validate_round({'base':rows,'head':rows},{'base':evidence,'head':evidence})

    def test_equal_partial_inventories_fail(self):
        rows,evidence=self.complete();evidence.pop(next(iter(evidence)))
        with self.assertRaisesRegex(ValueError,'oracle inventory'):
            comparison.validate_round({'base':rows,'head':rows},{'base':evidence,'head':evidence})

    def test_semantic_mismatch_fails(self):
        rows,evidence=self.complete();other=json.loads(json.dumps(evidence))
        other[next(iter(other))]['result']['Bytes']+=1
        with self.assertRaisesRegex(ValueError,'semantic mismatch'):
            comparison.validate_round({'base':rows,'head':rows},{'base':evidence,'head':other})

    def test_missing_field_digest_fails(self):
        rows,evidence=self.complete()
        name=next(n for n in evidence if '/full/' in n);evidence[name]['result']['FieldDigest']=''
        with self.assertRaisesRegex(ValueError,'semantic digest'):
            comparison.validate_round({'base':rows,'head':rows},{'base':evidence,'head':evidence})

    def test_revision_claim_is_checked(self):
        with patch.object(comparison.subprocess,'check_output',return_value='actual\n'):
            with self.assertRaisesRegex(ValueError,'revision'):
                comparison.git_state(Path('.'),'wrong')

    def test_dirty_revision_is_rejected(self):
        with patch.object(comparison.subprocess,'check_output',side_effect=['actual\n','?? untracked-input.go\n']):
            with self.assertRaisesRegex(ValueError,'must be clean'):
                comparison.git_state(Path('.'),'actual')

    def test_missing_metrics_fail(self):
        rows,evidence=self.complete()
        next(iter(rows.values())).pop('allocs/op')
        with self.assertRaisesRegex(ValueError,'metrics'):
            comparison.validate_round({'base':rows,'head':rows},{'base':evidence,'head':evidence})

    def test_wrong_cpu_fail(self):
        rows,evidence=self.complete()
        next(iter(rows.values()))['gomaxprocs']=8
        with self.assertRaisesRegex(ValueError,'CPU evidence'):
            comparison.validate_round({'base':rows,'head':rows},{'base':evidence,'head':evidence})

    def test_raw_profile_mismatch_fail(self):
        rows,evidence=self.complete();other=json.loads(json.dumps(evidence))
        other[next(iter(other))]['raw_profile_sha256']='e'*64
        with self.assertRaisesRegex(ValueError,'raw profile mismatch'):
            comparison.validate_round({'base':rows,'head':rows},{'base':evidence,'head':other})

    def test_duplicate_final_rows_fail(self):
        with self.assertRaisesRegex(ValueError,'duplicate final'):
            comparison.benchmark_rows('BenchmarkT06CaptureReader/case 1 100 ns/op\n'*2)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'evidence.jsonl'
            e={'benchmark':'BenchmarkT06CaptureReader/case','gomaxprocs':1,'iterations':100}
            p.write_text((json.dumps(e)+'\n')*2)
            with self.assertRaisesRegex(ValueError,'duplicate/non-increasing'):
                comparison.evidence_rows(p)

    def test_calibration_records_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'evidence.jsonl'
            p.write_text(''.join(json.dumps({'benchmark':'BenchmarkT06CaptureReader/case','gomaxprocs':1,'iterations':n})+'\n' for n in [1,10,100]))
            self.assertEqual(100,next(iter(comparison.evidence_rows(p).values()))['iterations'])

    def test_discovery_records_are_not_final_oracles(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'evidence.jsonl'
            e={'benchmark':'BenchmarkT06CaptureReader/case','gomaxprocs':4,'iterations':1}
            p.write_text((json.dumps(e)+'\n')*2)
            self.assertEqual({},comparison.evidence_rows(p))
            e['iterations']=100
            p.write_text(p.read_text()+json.dumps(e)+'\n')
            self.assertEqual(100,next(iter(comparison.evidence_rows(p).values()))['iterations'])


if __name__ == '__main__':
    unittest.main()
