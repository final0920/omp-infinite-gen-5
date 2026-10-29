"""Pure public-plan boundaries; no decoder, native engine or target executes."""
from pathlib import Path
import copy,sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'worker'))
from composition_selection import validate_plan,selected_addresses

class SelectionTests(unittest.TestCase):
    def test_exact_normalization_and_cross_template_repeats(self):
        plan={'strategy':'sequence','paths':[['0xABCDEF0123456789','0xffffffffffffffff'],['0xABCDEF0123456789']]}
        original=copy.deepcopy(plan);actual=validate_plan(plan)
        self.assertEqual(plan,original)
        self.assertEqual(actual['paths'][0],['0xabcdef0123456789','0xffffffffffffffff'])
        self.assertEqual(actual['indirect_mode'],'reject')
        self.assertEqual(selected_addresses(actual),actual['paths'][0])
    def test_loop_plan_and_explicit_guarded_mode(self):
        actual=validate_plan({'strategy':'constant-loop','prefix':['0x1'],'body':['0x2'],'suffix':[['0x3'],['0x1']], 'indirect_mode':'guarded-target'})
        self.assertEqual(selected_addresses(actual),['0x1','0x2','0x3'])
    def test_unknown_and_strategy_mixed_fields_refused(self):
        values=[None,[],{}, {'strategy':'other','paths':[['0x1']]},
                {'strategy':'sequence'}, {'strategy':'sequence','paths':[['0x1']],'body':['0x2']},
                {'strategy':'constant-loop','prefix':['0x1'],'body':['0x2']},
                {'strategy':'sequence','paths':[['0x1']],'repeat_count':32},
                {'strategy':'sequence','paths':[['0x1']],'certificate':{'valid':True}}]
        for value in values:
            with self.subTest(value=value),self.assertRaises(ValueError):validate_plan(value)
    def test_address_and_local_duplicate_boundaries(self):
        for path in ([],['0x0'],['0x1','0x01'],['0x10000000000000000'],[True],['1'],None):
            with self.subTest(path=path),self.assertRaises(ValueError):validate_plan({'strategy':'sequence','paths':[path]})
    def test_mode_and_application_boundaries(self):
        for mode in (None,True,'guarded',1):
            with self.assertRaises(ValueError):validate_plan({'strategy':'sequence','paths':[['0x1']],'indirect_mode':mode})
        for paths in ([],[['0x1']]*65):
            with self.assertRaises(ValueError):validate_plan({'strategy':'sequence','paths':paths})
        for suffix in ([],[['0x3']]*64):
            with self.assertRaises(ValueError):validate_plan({'strategy':'constant-loop','prefix':['0x1'],'body':['0x2'],'suffix':suffix})
    def test_provided_occurrences_and_distinct_address_limits(self):
        sixteen=[hex(i+1) for i in range(16)]
        self.assertEqual(len(validate_plan({'strategy':'sequence','paths':[sixteen]*64})['paths']),64)
        with self.assertRaises(ValueError):validate_plan({'strategy':'sequence','paths':[[hex(i+1) for i in range(17)]]*61})
        with self.assertRaises(ValueError):validate_plan({'strategy':'sequence','paths':[[hex(i+1) for i in range(128)],['0x81']]})
        with self.assertRaises(ValueError):validate_plan({'strategy':'sequence','paths':[[hex(i+1) for i in range(129)]]})

if __name__=='__main__':unittest.main()
