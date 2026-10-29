// IG5 API wrapper. Unmodified Ghidra libraries retain their upstream licenses.
// Byte data only: no ProgramDB, target execution, user scripts or IG5 native DLL.
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.pcode.*;

public final class IG5JavaProjectionDecode {
    private static String hex(long value) { return "0x" + Long.toUnsignedString(value, 16); }
    private static JsonObject node(Varnode value) {
        JsonObject result = new JsonObject();
        result.addProperty("space", value.getAddress().getAddressSpace().getName());
        result.addProperty("offset", hex(value.getOffset()));
        result.addProperty("size", value.getSize());
        return result;
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("Fixed installation/input/digest required");
        Path input = Path.of(args[1]);
        if (Files.size(input) > 65536) throw new IllegalArgumentException("Decoder input byte budget");
        byte[] raw = Files.readAllBytes(input);
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
        if (!digest.equals(args[2])) throw new IllegalArgumentException("Decoder input digest mismatch");
        JsonObject request = JsonParser.parseString(new String(raw, StandardCharsets.UTF_8)).getAsJsonObject();
        if (!request.keySet().equals(Set.of("schema", "targetSha256", "instructions")) ||
            !request.get("schema").getAsString().equals("ig5-java-projection-input-v1") ||
            !request.get("targetSha256").getAsString().matches("[a-f0-9]{64}"))
            throw new IllegalArgumentException("Decoder input scope");
        JsonArray rows = request.getAsJsonArray("instructions");
        if (rows.size() < 1 || rows.size() > 128) throw new IllegalArgumentException("Instruction count budget");
        ApplicationConfiguration config = new ApplicationConfiguration();
        config.setInitializeLogging(false);
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])), config);
        LanguageID id = new LanguageID("x86:LE:64:default");
        SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();
        List<LanguageDescription> candidates = Arrays.stream(provider.getLanguageDescriptions())
            .filter(d -> d.getLanguageID().equals(id)).toList();
        if (candidates.size() != 1 || !(candidates.get(0) instanceof SleighLanguageDescription description))
            throw new IllegalStateException("Fixed language description unavailable");
        File languages = new File(args[0], "Ghidra/Processors/x86/data/languages");
        if (!description.getSlaFile().getCanonicalPath().equals(new File(languages, "x86-64.sla").getCanonicalPath()) ||
            !description.getSpecFile().getCanonicalPath().equals(new File(languages, "x86-64.pspec").getCanonicalPath()))
            throw new IllegalStateException("Fixed language file binding mismatch");
        Language language = provider.getLanguage(id);
        if (language == null) throw new IllegalStateException("Language loading failed");
        AddressFactory factory = language.getAddressFactory();
        JsonArray spaces = new JsonArray();
        for (AddressSpace space : factory.getAddressSpaces()) {
            JsonObject row = new JsonObject();
            row.addProperty("space", space.getName());
            row.addProperty("javaSpaceId", space.getSpaceID());
            row.addProperty("uniqueIndex", space.getUnique());
            spaces.add(row);
        }
        JsonArray instructions = new JsonArray();
        Set<Long> seen = new HashSet<>();
        int operations = 0;
        for (JsonElement element : rows) {
            JsonObject row = element.getAsJsonObject();
            if (!row.keySet().equals(Set.of("ea", "codeBytes"))) throw new IllegalArgumentException("Instruction input scope");
            String ea = row.get("ea").getAsString(), bytes = row.get("codeBytes").getAsString();
            if (!ea.matches("0x[0-9a-f]{1,16}") || !bytes.matches("(?:[0-9a-f]{2}){1,15}"))
                throw new IllegalArgumentException("Instruction input encoding");
            long offset = Long.parseUnsignedLong(ea.substring(2), 16);
            if (offset == 0 || !seen.add(offset)) throw new IllegalArgumentException("Repeated or zero instruction address");
            byte[] code = HexFormat.of().parseHex(bytes);
            Address address = factory.getDefaultAddressSpace().getAddress(offset);
            ProcessorContextImpl context = new ProcessorContextImpl(language);
            String[] names = {"longMode", "addrsize", "opsize"};
            int[] values = {1, 2, 1};
            for (int i = 0; i < names.length; i++) {
                Register register = language.getRegister(names[i]);
                if (register == null) throw new IllegalStateException("Missing fixed processor context");
                context.setValue(register, BigInteger.valueOf(values[i]));
            }
            ByteMemBufferImpl buffer = new ByteMemBufferImpl(address, code, false);
            InstructionPrototype prototype = language.parse(buffer, context, false);
            int length = prototype.getLength();
            if (length < 1 || length > Math.min(15, code.length)) throw new IllegalStateException("Instruction boundary exceeds available bytes");
            PseudoInstruction instruction = new PseudoInstruction(factory, address, prototype, buffer, context);
            JsonObject decoded = new JsonObject();
            decoded.addProperty("ea", hex(offset));
            decoded.addProperty("size", length);
            decoded.addProperty("codeBytes", HexFormat.of().formatHex(Arrays.copyOf(code, length)));
            decoded.addProperty("mnemonic", instruction.getMnemonicString());
            StringJoiner operands = new StringJoiner(",");
            for (int i = 0; i < instruction.getNumOperands(); i++) operands.add(instruction.getDefaultOperandRepresentation(i));
            decoded.addProperty("operands", operands.toString());
            PcodeOp[] rawPcode = instruction.getPcode();
            if (rawPcode.length > 4096) throw new IllegalStateException("Per-instruction pcode budget");
            JsonArray pcode = new JsonArray();
            for (PcodeOp op : rawPcode) {
                if (++operations > 65536 || op.getNumInputs() > 64) throw new IllegalStateException("Raw pcode budget");
                JsonObject item = new JsonObject();
                item.addProperty("opcode", op.getMnemonic());
                item.add("output", op.getOutput() == null ? JsonNull.INSTANCE : node(op.getOutput()));
                JsonArray inputs = new JsonArray();
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode value = op.getInput(i);
                    if (i == 0 && (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE)) {
                        if (!value.isConstant()) throw new IllegalStateException("Invalid memory space operand");
                        AddressSpace space = factory.getAddressSpace((int)value.getOffset());
                        if (space == null) throw new IllegalStateException("Unknown memory space operand");
                        JsonObject normalized = new JsonObject();
                        normalized.addProperty("kind", "address-space");
                        normalized.addProperty("space", space.getName());
                        normalized.addProperty("spaceId", space.getUnique());
                        inputs.add(normalized);
                    } else inputs.add(node(value));
                }
                item.add("inputs", inputs);
                pcode.add(item);
            }
            decoded.add("pcode", pcode);
            instructions.add(decoded);
        }
        JsonObject result = new JsonObject();
        result.addProperty("schema", "ig5-java-projection-decode-v1");
        result.addProperty("language", id.toString());
        result.addProperty("targetSha256", request.get("targetSha256").getAsString());
        result.addProperty("inputSha256", digest);
        result.addProperty("nativeTargetExecuted", false);
        result.addProperty("databaseModified", false);
        result.add("addressSpaces", spaces);
        result.add("instructions", instructions);
        byte[] output = ("IG5_JAVA_JSON:" + new GsonBuilder().serializeNulls().create().toJson(result) + "\n").getBytes(StandardCharsets.UTF_8);
        if (output.length > 4194304) throw new IllegalStateException("Decoder output byte budget");
        System.out.write(output);
    }
}
