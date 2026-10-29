"""Test oracle: original pure Python SCCP only. No native Ghidra/decoder/target execution."""
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'adapters'/'ghidra'))
from deobfuscation_analysis import analyze_deobfuscation
data=sys.stdin.buffer.read(2*1024*1024+1)
if len(data)>2*1024*1024:raise ValueError('Bounded fixture input required')
graph=json.loads(data)
print(json.dumps(analyze_deobfuscation(graph),separators=(',',':')))
