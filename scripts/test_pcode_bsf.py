"""Pure complete-shape/frame regression; no native decoder or PE executes."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_pcode_projection import (GPRS,ProjectionError,RAM,append_path,const,
                                   evaluate,flag,ins,op,project,reg,target,tmp)


def bounded_bsf(bits=16,destination='r9',source='r15',unique_base=0x1000):
    width=bits//8;names=list(GPRS);dst,src=names.index(destination),names.index(source)
    rex=0x40|(8 if bits==64 else 0)|(4 if dst>=8 else 0)|(1 if src>=8 else 0)
    code=([0x66] if bits==16 else [])+([rex] if rex!=0x40 else [])+[0x0f,0xbc,0xc0|((dst&7)<<3)|(src&7)]
    counter,zero,shifted,low,nonzero=(tmp(unique_base+i*0x100,size) for i,size in enumerate((width,1,width,width,1)))
    operations=[op('COPY',counter,const(0,width)),
        op('INT_EQUAL',flag('zf'),reg(source,width),const(0,width)),
        op('INT_EQUAL',zero,flag('zf'),const(1,1)),
        op('CBRANCH',None,const(7,4),zero),
        op('INT_RIGHT',shifted,reg(source,width),counter),
        op('INT_AND',low,shifted,const(1,width)),
        op('INT_NOTEQUAL',nonzero,low,const(0,width)),
        op('CBRANCH',None,const(3,4),nonzero),
        op('INT_ADD',counter,counter,const(1,width)),
        op('BRANCH',None,const(0xfffffffb,4)),
        op('COPY',reg(destination,width),counter)]
    if bits==32:operations.append(op('INT_ZEXT',reg(destination),reg(destination,4)))
    return ins(*operations,mnemonic='BSF',code=bytes(code).hex())


class BsfProjectionTests(unittest.TestCase):
    def test_dead_frame_is_bound_raw_preserved_and_budget_not_reduced(self):
        for bits,steps in ((16,99),(32,196),(64,387)):
            with self.subTest(bits=bits):
                instruction=bounded_bsf(bits);original=copy.deepcopy(instruction)
                result=project([instruction],['rax']);e=result['internalElisions'][0]
                self.assertEqual(instruction,original)
                self.assertEqual(e['kind'],'register-bsf-bounded-dead-frame-v1')
                self.assertEqual(e['maximumPcodeSteps'],steps)
                self.assertEqual(e['maximumBackedges'],bits-1)
                self.assertEqual(e['internalEdges'],[[3,10],[7,10],[9,4]])
                self.assertEqual(e['zeroInputRawDestination'],0)
                self.assertEqual(e['zeroInputArchitecturalDestination'],'undefined')
                self.assertEqual(e['rawOperationCount'],12 if bits==32 else 11)
                self.assertEqual(result['statistics']['pcodeOperations'],len(instruction['pcode']))
                self.assertEqual(result['statistics']['selectedOperations'],0)
                self.assertEqual(result['statistics']['omittedInternalControlOperations'],3)
                self.assertEqual(result['statistics']['omittedPureOperations'],len(instruction['pcode'])-3)
                self.assertEqual(result['flagPolicies'][0]['family'],'bsf-complete-bounded-shape')
                self.assertEqual(e['frameLiveIntersection'],[])
                self.assertFalse(e['architectureProved'])

    def test_live_destination_all_widths_rejected(self):
        for bits in (16,32,64):
            with self.subTest(bits=bits),self.assertRaisesRegex(ProjectionError,'Live BSF'):
                project([bounded_bsf(bits)],['r9'])

    def test_every_register_binding_self_source_and_alpha_renaming(self):
        for bits in (16,32,64):
            for destination in GPRS:
                for source in GPRS:
                    result=project([bounded_bsf(bits,destination,source,0x654320)],['rax' if destination!='rax' else 'r8'])
                    evidence=result['internalElisions'][0]
                    self.assertEqual((evidence['sourceOffset'],evidence['destinationOffset']),(GPRS[source],GPRS[destination]))

    def test_partial_overwrite_does_not_hide_full_frame(self):
        low16=ins(op('COPY',reg('r9',2),const(0x55,2)),mnemonic='MOV',code='6641b95500')
        result=project(append_path(bounded_bsf(16),low16),['r9'])
        self.assertEqual(evaluate(result,{'r9':0x123456789abcdef0})[0],{'r9':0x123456789abc0055})
        for bits in (32,64):
            with self.subTest(bits=bits),self.assertRaisesRegex(ProjectionError,'Live BSF'):
                project(append_path(bounded_bsf(bits),copy.deepcopy(low16)),['r9'])
        low32=ins(op('COPY',reg('r9',4),const(0x55,4)),mnemonic='MOV',code='41b955000000')
        with self.assertRaisesRegex(ProjectionError,'Live BSF'):
            project(append_path(bounded_bsf(32),low32),['r9'])
        low32['pcode'].append(op('INT_ZEXT',reg('r9'),reg('r9',4)))
        self.assertEqual(evaluate(project(append_path(bounded_bsf(32),low32),['r9']),{})[0],{'r9':0x55})

    def test_every_status_flag_is_a_live_barrier(self):
        for name in ('cf','pf','af','zf','sf','of'):
            read=ins(op('COPY',reg('rax',1),flag(name)),mnemonic='MOV',code='88d8')
            with self.subTest(flag=name),self.assertRaisesRegex(ProjectionError,'Live BSF'):
                project(append_path(bounded_bsf(),read),['rax'])

    def test_store_address_value_and_transitive_read_are_roots(self):
        suffixes=[ins(op('STORE',None,RAM,reg('rax'),reg('r9')),mnemonic='MOV',code='4c8908'),
                  ins(op('STORE',None,RAM,reg('r9'),reg('rax')),mnemonic='MOV',code='498901'),
                  ins(op('COPY',reg('rax'),reg('r9')),mnemonic='MOV',code='4c89c8')]
        for suffix in suffixes:
            overwrite=ins(op('COPY',reg('r9'),const(0)),mnemonic='MOV',code='49b90000000000000000')
            with self.assertRaisesRegex(ProjectionError,'Live BSF'):
                project(append_path(bounded_bsf(),suffix,overwrite),['rax'])

    def test_prior_flags_cannot_cross_bsf_but_later_definition_can(self):
        stc=ins(op('COPY',flag('cf'),const(1,1)),mnemonic='STC',code='f9')
        read=ins(op('COPY',reg('rax',1),flag('cf')),mnemonic='SETC',code='0f92c0')
        with self.assertRaisesRegex(ProjectionError,'Live BSF'):
            project(append_path(copy.deepcopy(stc),bounded_bsf(),copy.deepcopy(read)),['rax'])
        result=project(append_path(bounded_bsf(),stc,read),['rax'])
        self.assertEqual(evaluate(result,{'rax':0})[0],{'rax':1})

    def test_prior_store_preserved_in_order_with_wrapping_address(self):
        store=ins(op('STORE',None,RAM,reg('rax'),reg('r9')),mnemonic='MOV',code='4c8908')
        result=project(append_path(store,bounded_bsf()),['rax'])
        _,values=evaluate(result,{'rax':(1<<64)-4,'r9':0x0102030405060708})
        self.assertEqual(len(result['stores']),1)
        self.assertEqual(result['stores'][0]['instructionIndex'],0)
        self.assertEqual(values[result['currentMemory']][0],4)

    def test_each_internal_edge_counter_and_low_bit_mask_must_match(self):
        changes=[(0,0,'0x1'),(2,1,'0x0'),(3,0,'0x6'),(5,1,'0x2'),
                 (7,0,'0x2'),(8,1,'0x0'),(8,1,'0x2'),(9,0,'0xfffffffc'),(4,0,'0xb0')]
        for index,which,offset in changes:
            item=bounded_bsf();item['pcode'][index]['inputs'][which]['offset']=offset
            with self.subTest(change=(index,offset)),self.assertRaisesRegex(ProjectionError,'Internal p-code'):
                project([item],['rax'])
        for opcode in ('INT_SRIGHT','STORE','CALL','CALLOTHER','INT_SUB'):
            item=bounded_bsf();item['pcode'][4]['opcode']=opcode
            with self.subTest(opcode=opcode),self.assertRaisesRegex(ProjectionError,'Internal p-code'):
                project([item],['rax'])

    def test_memory_tzcnt_width_prefix_and_mnemonic_cannot_match(self):
        for code in ('66450fbc0f','f3450fbccf','f0450fbccf','f2450fbccf','66450fbdcf',
                     '4d0fbccf','6666450fbccf','45660fbccf','6645450fbccf','664d0fbccf'):
            item=bounded_bsf();item.update(codeBytes=code,size=len(code)//2)
            with self.subTest(code=code),self.assertRaisesRegex(ProjectionError,'Internal p-code'):
                project([item],['rax'])
        for key,value in (('codeBytes',None),('mnemonic','TZCNT'),('mnemonic','BSR')):
            item=bounded_bsf();item[key]=value
            with self.assertRaises(ProjectionError):project([item],['rax'])

    def test_every_unique_role_is_disjoint_and_width_bound(self):
        for index in (2,4,5,6):
            item=bounded_bsf();item['pcode'][index]['output']['offset']=item['pcode'][0]['output']['offset']
            with self.subTest(index=index),self.assertRaisesRegex(ProjectionError,'Overlapping'):
                project([item],['rax'])
        item=bounded_bsf();item['pcode'][5]['output']['size']=1
        with self.assertRaisesRegex(ProjectionError,'temporary role'):project([item],['rax'])

    def test_full32_zero_extension_required(self):
        for change in ('missing','signed','other-register'):
            item=bounded_bsf(32)
            if change=='missing':item['pcode'].pop()
            elif change=='signed':item['pcode'][-1]['opcode']='INT_SEXT'
            else:item['pcode'][-1]['output']['offset']=hex(GPRS['r8'])
            with self.subTest(change=change),self.assertRaisesRegex(ProjectionError,'Internal p-code'):
                project([item],['rax'])

    def test_annotations_extra_effect_and_path_gap_cannot_authorize(self):
        item=bounded_bsf();item['pcode'][9]['inputs'][0]['offset']='0x0'
        item['internalElisions']=[{'frameLiveIntersection':[]}]
        item['bsfDescriptor']={'frameRegisterBytes':[]}
        with self.assertRaisesRegex(ProjectionError,'Internal p-code'):project([item],['rax'])
        item=bounded_bsf();item['pcode'].append(op('STORE',None,RAM,reg('rax'),reg('rbx')))
        with self.assertRaisesRegex(ProjectionError,'Internal p-code'):project([item],['rax'])
        path=append_path(bounded_bsf(),ins(mnemonic='NOP',code='90'));path[-1]['ea']='0x2000'
        with self.assertRaisesRegex(ProjectionError,'Missing fallthrough'):project(path,['rax'])

    def test_guarded_side_exit_observes_bsf_before_later_overwrite(self):
        first=bounded_bsf(64,'rax','rbx')
        branch=ins(op('INT_EQUAL',tmp(0,1),reg('rcx'),const(0)),
                   op('CBRANCH',None,target(0x2000),tmp(0,1)),mnemonic='JRCXZ',code='e300')
        last=ins(op('COPY',reg('rax'),const(0x55)),mnemonic='MOV',code='b855000000')
        with self.assertRaisesRegex(ProjectionError,'Live BSF'):
            project(append_path(first,branch,last),['rax'],mode='guarded-path')

    def test_remainder_all_unsigned_byte_values_and_nonzero_divisors(self):
        for divisor in range(1,256):
            result=project([ins(op('INT_REM',reg('rax',1),reg('rbx',1),const(divisor,1)))],['rax'])
            for dividend in range(256):
                actual=evaluate(result,{'rax':0x123456789abcde00,'rbx':dividend})[0]['rax']
                quotient=dividend//divisor
                self.assertEqual(actual,0x123456789abcde00|(dividend-quotient*divisor))

    def test_remainder_wide_values_preserve_unsigned_width(self):
        for width in (2,4,8):
            mask=(1<<(8*width))-1
            for divisor in (1,17,mask):
                path=[ins(op('INT_REM',reg('rax',width),reg('rbx',width),const(divisor,width)))]
                result=project(path,['rax'])
                for value in (0,1,16,17,mask-1,mask):
                    actual=evaluate(result,{'rbx':value,'rax':0})[0]['rax']
                    self.assertEqual(actual,value-(value//divisor)*divisor)

    def test_remainder_zero_or_symbolic_divisor_rejected_before_slicing(self):
        for divisor in (const(0),reg('rcx')):
            item=ins(op('INT_REM',reg('rax'),reg('rbx'),divisor))
            with self.assertRaisesRegex(ProjectionError,'nonzero immediate divisor'):
                project([item],['r15'])
        item=ins(op('INT_REM',reg('rax'),reg('rbx'),const(17,4)))
        with self.assertRaisesRegex(ProjectionError,'arithmetic width mismatch'):
            project([item],['r15'])


if __name__=='__main__':unittest.main()
