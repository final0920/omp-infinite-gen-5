import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.Reference;
import org.jf.dexlib2.iface.reference.StringReference;
import org.jf.dexlib2.iface.reference.TypeReference;
import org.jf.dexlib2.util.ReferenceUtil;

/**
 * Independent reference reader for the IG5 DEX tests: prints what dexlib2 (the smali project's reader) sees.
 *   DexDump <file.dex>   one line per class, method, instruction and reference
 *   DexDump --opcodes    the opcode values dexlib2 defines
 * Strings are printed as UTF-16BE hex so no platform charset can alter them.
 */
public class DexDump {
    // Android 9 (API 28) = DEX 039: invoke-polymorphic, invoke-custom, const-method-handle and const-method-type are present, ODEX-only opcodes are not.
    static final int API = 28;

    static String hex(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_16BE)) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        PrintStream out = new PrintStream(System.out, false, "UTF-8");
        if (args[0].equals("--opcodes")) {
            Opcodes defined = Opcodes.forApi(API);
            for (Opcode op : Opcode.values()) { Short v = defined.getOpcodeValue(op); if (v != null) out.println("OPCODE " + v + " " + op.name + " " + op.format.size); }
            out.flush();
            return;
        }
        Opcodes opcodes = Opcodes.forApi(API);
        DexBackedDexFile dex = DexFileFactory.loadDexFile(new File(args[0]), opcodes);
        for (ClassDef c : dex.getClasses()) {
            out.println("CLASS " + c.getType() + " " + c.getAccessFlags() + " " + c.getSuperclass());
            for (Method m : c.getMethods()) {
                MethodImplementation impl = m.getImplementation();
                out.println("METHOD " + ReferenceUtil.getMethodDescriptor(m) + " " + m.getAccessFlags() + " " + (impl != null));
                if (impl == null) continue;
                for (Instruction i : impl.getInstructions()) {
                    Opcode op = i.getOpcode();
                    out.println("OP " + opcodes.getOpcodeValue(op) + " " + i.getCodeUnits());
                    if (i instanceof ReferenceInstruction) {
                        Reference r = ((ReferenceInstruction) i).getReference();
                        if (r instanceof MethodReference) out.println("INVOKE " + ReferenceUtil.getMethodDescriptor((MethodReference) r));
                        else if (r instanceof StringReference) out.println("STRING " + hex(((StringReference) r).getString()));
                        else if (r instanceof FieldReference) out.println("FIELD " + ReferenceUtil.getFieldDescriptor((FieldReference) r));
                        else if (r instanceof TypeReference) out.println("TYPE " + ((TypeReference) r).getType());
                    }
                }
            }
        }
        out.flush();
    }
}
