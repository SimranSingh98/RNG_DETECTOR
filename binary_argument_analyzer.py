import re
import sys
import subprocess
from collections import defaultdict

# ============================================================
# CRYPTOGRAPHIC / RNG API DEFINITIONS
# ============================================================

RNG_APIS = {
    "BCryptGenRandom",
    "CryptGenRandom",
}

CRYPTO_APIS = {
    "BCryptEncrypt",
    "BCryptDecrypt",
    "BCryptGenerateSymmetricKey",
    "BCryptOpenAlgorithmProvider",
    "BCryptSetProperty",
    "BCryptGetProperty",
}


# ============================================================
# CONFIGURATION
# ============================================================

TARGET_APIS = {
    "BCryptGenRandom",
    "BCryptOpenAlgorithmProvider",
    "BCryptSetProperty",
    "BCryptGetProperty",
    "BCryptGenerateSymmetricKey",
    "BCryptEncrypt",
}


# ============================================================
# PE IMPORT PARSING
# ============================================================

def parse_imports(binary):

    result = subprocess.run(
        ["llvm-objdump", "-p", binary],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    lines = result.stdout.splitlines()

    imports = {}

    # --------------------------------------------------------
    # Find PE image base
    #
    # llvm-objdump -p normally contains something like:
    #
    # ImageBase 0000000140000000
    #
    # --------------------------------------------------------

    image_base = None

    for line in lines:

        m = re.search(
            r"ImageBase\s+([0-9a-fA-F]+)",
            line,
            re.IGNORECASE
        )

        if m:

            image_base = int(
                m.group(1),
                16
            )

            break

    if image_base is None:

        print(
            "ERROR: Could not determine PE image base."
        )

        sys.exit(1)

    print(
        f"PE Image Base: 0x{image_base:x}"
    )

    # --------------------------------------------------------
    # Parse import table
    # --------------------------------------------------------

    current_dll = None
    current_iat = None

    for line in lines:

        # ----------------------------------------------------
        # New import table
        #
        # Example:
        #
        # lookup 000209c8 time 00000000 fwd 00000000
        # name 000214bc addr 00020c50
        #
        # The "addr" value is an RVA.
        # We convert it to a VA using image_base.
        # ----------------------------------------------------

        m = re.search(
            r"lookup\s+[0-9a-fA-F]+\s+"
            r"time\s+[0-9a-fA-F]+\s+"
            r"fwd\s+[0-9a-fA-F]+\s+"
            r"name\s+[0-9a-fA-F]+\s+"
            r"addr\s+([0-9a-fA-F]+)",
            line,
            re.IGNORECASE
        )

        if m:

            iat_rva = int(
                m.group(1),
                16
            )

            current_iat = (
                image_base + iat_rva
            )

            continue

        # ----------------------------------------------------
        # DLL name
        # ----------------------------------------------------

        m = re.search(
            r"DLL Name:\s+(.+)",
            line,
            re.IGNORECASE
        )

        if m:

            current_dll = m.group(1).strip()

            continue

        # ----------------------------------------------------
        # Imported API
        #
        # Example:
        #
        #     20  BCryptEncrypt
        #
        # ----------------------------------------------------

        m = re.match(
            r"^\s*\d+\s+"
            r"([A-Za-z_][A-Za-z0-9_@?$]*)\s*$",
            line
        )

        if (
            m
            and current_dll
            and current_iat is not None
        ):

            api = m.group(1)

            imports[current_iat] = {
                "dll": current_dll,
                "api": api
            }

            # ------------------------------------------------
            # Windows x64 IAT entries are 8 bytes.
            # ------------------------------------------------

            current_iat += 8

    return imports


# ============================================================
# DISASSEMBLY
# ============================================================

def get_disassembly(binary):

    result = subprocess.run(
        ["llvm-objdump", "-d", binary],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    return result.stdout


# ============================================================
# PARSE INSTRUCTIONS
# ============================================================

INSTRUCTION_RE = re.compile(
    r"^([0-9a-fA-F]+):\s+"
    r"((?:[0-9a-fA-F]{2}\s+)+)"
    r"(.+)$"
)


def parse_instructions(disassembly):

    instructions = []

    for line in disassembly.splitlines():

        m = INSTRUCTION_RE.match(line.strip())

        if not m:
            continue

        address = int(m.group(1), 16)

        asm = m.group(3).strip()

        instructions.append({
            "address": address,
            "asm": asm,
        })

    return instructions


# ============================================================
# INTEGER / ADDRESS HELPERS
# ============================================================

def normalize_register(reg):

    reg = reg.strip()

    # LLVM AT&T syntax uses % before registers.
    reg = reg.lstrip("%")

    reg = reg.upper()

    aliases = {
        "EAX": "RAX",
        "EBX": "RBX",
        "ECX": "RCX",
        "EDX": "RDX",
        "ESI": "RSI",
        "EDI": "RDI",

        "R8D": "R8",
        "R9D": "R9",
        "R10D": "R10",
        "R11D": "R11",
        "R12D": "R12",
        "R13D": "R13",
        "R14D": "R14",
        "R15D": "R15",

        "RIP": "RIP",
        "RSP": "RSP",
        "RBP": "RBP",
        "RSI": "RSI",
        "RDI": "RDI",
    }

    return aliases.get(reg, reg)

def parse_immediate(value):

    value = value.strip()

    # LLVM AT&T syntax uses $ before immediates.
    value = value.lstrip("$")

    try:

        if value.startswith("-0x"):

            return -int(value[3:], 16)

        if value.startswith("0x"):

            return int(value, 16)

        return int(value)

    except ValueError:

        return None
    
# ============================================================
# SYMBOLIC STATE
# ============================================================

class SymbolicState:

    def __init__(self):

        # --------------------------------------------------------
        # Symbolic value of registers
        # --------------------------------------------------------

        self.registers = {
            "RCX": "ARG1",
            "RDX": "ARG2",
            "R8":  "ARG3",
            "R9":  "ARG4",
        }

        # --------------------------------------------------------
        # Symbolic value of stack memory
        # --------------------------------------------------------

        self.memory = {}

        # --------------------------------------------------------
        # Stack frame offset from caller's pre-CALL RSP
        # --------------------------------------------------------

        self.frame_delta = 0

        # --------------------------------------------------------
        # Caller's symbolic state for cross-frame resolution
        # --------------------------------------------------------

        self.caller_state = None

        # --------------------------------------------------------
        # Provenance / history
        #
        # Example:
        #
        # RDX:
        #     ARG1
        #     -> RCX
        #     -> [RSP+0x30]
        #     -> RDX
        # --------------------------------------------------------

        self.register_history = {
            "RCX": ["ARG1"],
            "RDX": ["ARG2"],
            "R8":  ["ARG3"],
            "R9":  ["ARG4"],
        }

        self.memory_history = {}

    # --------------------------------------------------------
    # REGISTER
    # --------------------------------------------------------

    def set_reg(self, reg, value, history=None):

        reg = normalize_register(reg)

        self.registers[reg] = value

        if history is None:

            history = [value]

        self.register_history[reg] = history

    def get_reg(self, reg):

        reg = normalize_register(reg)

        return self.registers.get(
            reg,
            "UNKNOWN"
        )

    def get_reg_history(self, reg):

        reg = normalize_register(reg)

        return self.register_history.get(
            reg,
            ["UNKNOWN"]
        )

    # --------------------------------------------------------
    # MEMORY
    # --------------------------------------------------------

    def set_mem(self, location, value, history=None):

        self.memory[location] = value

        if history is None:

            history = [value]

        self.memory_history[location] = history

    def get_mem(self, location):

        return self.memory.get(
            location,
            "UNKNOWN"
        )

    def get_mem_history(self, location):

        return self.memory_history.get(
            location,
            ["UNKNOWN"]
        )

    # --------------------------------------------------------
    # DEBUG
    # --------------------------------------------------------

    def dump_registers(self):

        regs = [
            "RCX",
            "RDX",
            "R8",
            "R9",
            "RSI",
            "RDI",
            "RAX"
        ]

        for reg in regs:

            value = self.get_reg(reg)

            print(
                f"{reg:<5}= {value}"
            )

    # --------------------------------------------------------
    # PROVENANCE DEBUG
    # --------------------------------------------------------

    def dump_provenance(self):

        print("\nREGISTER PROVENANCE")
        print("-" * 70)

        regs = [
            "RCX",
            "RDX",
            "R8",
            "R9",
            "RSI",
            "RDI",
            "RAX"
        ]

        for reg in regs:

            history = self.get_reg_history(reg)

            print(
                f"{reg:<5}= "
                + " -> ".join(history)
            )

        print("\nMEMORY PROVENANCE")
        print("-" * 70)

        if not self.memory_history:

            print("No tracked memory provenance.")

            return

        for location, history in self.memory_history.items():

            print(
                f"{location:<15}= "
                + " -> ".join(history)
            )

# ============================================================
# OPERAND HELPERS
# ============================================================

def clean_operand(op):

    return op.strip()


def is_register(op):

    op = normalize_register(op)

    return op in {
        "RAX",
        "RBX",
        "RCX",
        "RDX",
        "RSI",
        "RDI",
        "RBP",
        "RSP",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "R13",
        "R14",
        "R15",
    }


def memory_location(op):

    """
    Convert memory operands with register base:

        (%rax)      -> [RAX]
        0x8(%rax)   -> [RAX+0x8]
        -0x10(%rcx) -> [RCX-0x10]
    """

    op = op.strip()

    # Match: optional_offset(register)
    # Groups: (1) optional offset, (2) register name
    m = re.match(
        r"(-?0x[0-9a-fA-F]+|-?\d+)?\(%([a-z0-9]+)\)",
        op
    )

    if not m:
        return None

    offset_str = m.group(1)
    reg_name = m.group(2)

    # Normalize the register
    reg = normalize_register("%" + reg_name)

    # Validate it's a real register
    if not is_register(reg):
        return None

    # No offset
    if offset_str is None:
        return f"[{reg}]"

    # Parse offset
    offset = parse_immediate(offset_str)

    if offset is None:
        return None

    # Format with offset
    if offset >= 0:
        return f"[{reg}+0x{offset:X}]"
    else:
        return f"[{reg}-0x{-offset:X}]"

# ============================================================
# SYMBOLIC OPERAND VALUE
# ============================================================

def resolve_operand(op, state):

    op = clean_operand(op)

    # Register
    if is_register(op):

        return state.get_reg(op)

    # Immediate
    imm = parse_immediate(op)

    if imm is not None:

        return str(imm)

    # Memory
    mem = memory_location(op)

    if mem:

        value = state.get_mem(mem)

        # ------------------------------------------------
        # If not found and RSP-relative, try translated
        # location in caller's frame (cross-frame resolution)
        # ------------------------------------------------

        if value == "UNKNOWN" and state.frame_delta != 0 and state.caller_state is not None:

            translated_mem = translate_rsp_memory_location(
                mem,
                state.frame_delta
            )

            if translated_mem is not None:

                caller_value = state.caller_state.get_mem(translated_mem)

                if caller_value != "UNKNOWN":

                    # print(
                    #     f"DEBUG CROSS-FRAME RESOLVE: "
                    #     f"operand={mem}, "
                    #     f"frame_delta=0x{state.frame_delta:X}, "
                    #     f"caller_location={translated_mem}, "
                    #     f"caller_value={caller_value}"
                    # )

                    value = caller_value

                else:

                    print(
                        f"DEBUG FRAME LOOKUP: "
                        f"{mem} -> {translated_mem}, "
                        f"frame_delta=0x{state.frame_delta:X} (not in caller)"
                    )

        elif value == "UNKNOWN" and state.frame_delta != 0:

            translated_mem = translate_rsp_memory_location(
                mem,
                state.frame_delta
            )

            if translated_mem is not None:

                print(
                    f"DEBUG FRAME LOOKUP: "
                    f"{mem} -> {translated_mem}, "
                    f"frame_delta=0x{state.frame_delta:X}"
                )

                value = state.get_mem(translated_mem)

        return value

    return "UNKNOWN"


# ============================================================
# SYMBOLIC INSTRUCTION EXECUTION
# ============================================================

def process_instruction(ins, state):

    asm = ins["asm"]

    # Remove comments
    asm = asm.split("#")[0].strip()

    if not asm:
        return

    parts = asm.split(None, 1)

    if len(parts) != 2:
        mnemonic = parts[0]
        operands = []
    else:
        mnemonic = parts[0].lower()
        operands = [
            x.strip()
            for x in parts[1].split(",")
        ]

    # --------------------------------------------------------
    # XOR REG, REG
    # --------------------------------------------------------

    if mnemonic == "xorl" or mnemonic == "xorq":

        if len(operands) == 2:

            dst = operands[0]
            src = operands[1]

            if normalize_register(dst) == normalize_register(src):

                state.set_reg(dst, "0")

        return

    # --------------------------------------------------------
    # MOV
    # --------------------------------------------------------

    if mnemonic in {
        "movq",
        "movl",
        "movw",
        "movb"
    }:

        if len(operands) != 2:
            return

        src = operands[0]
        dst = operands[1]

        value = resolve_operand(
            src,
            state
        )

        # ----------------------------------------------------
        # Get provenance of source
        # ----------------------------------------------------

        if is_register(src):

            history = state.get_reg_history(src).copy()

        else:

            mem = memory_location(src)

            if mem:

                history = state.get_mem_history(mem).copy()

            else:

                imm = parse_immediate(src)

                if imm is not None:

                    history = [
                        f"IMM({src})"
                    ]

                else:

                    history = [
                        "UNKNOWN"
                    ]

        # ----------------------------------------------------
        # Add destination to provenance
        # ----------------------------------------------------

        if is_register(dst):

            new_history = history + [
                normalize_register(dst)
            ]

            state.set_reg(
                dst,
                value,
                new_history
            )

            return

        # ----------------------------------------------------
        # Destination memory
        # ----------------------------------------------------

        mem = memory_location(dst)

        if mem:

            new_history = history + [
                mem
            ]

            state.set_mem(
                mem,
                value,
                new_history
            )

            return

    # --------------------------------------------------------
    # LEA
    # --------------------------------------------------------

    if mnemonic == "leaq":

        if len(operands) != 2:
            return

        src = operands[0]
        dst = operands[1]

        mem = memory_location(src)

        if mem:

            value = "&" + mem

            history = [
                mem,
                normalize_register(dst)
            ]

            state.set_reg(
                dst,
                value,
                history
            )

        return

    # --------------------------------------------------------
    # MOVABS / MOVZ / etc.
    # --------------------------------------------------------

    # For now these remain UNKNOWN.


# ============================================================
# API CALL RESOLUTION
# ============================================================

def resolve_api_call(call_target, imports):

    """
    Resolve:

        CALL -> import thunk -> IAT

    We do this by looking for a thunk:

        jmpq *0xOFFSET(%rip) # 0xIAT
    """

    return None


# ============================================================
# FIND IMPORT THUNKS
# ============================================================

def find_thunks(disassembly):

    """
    Parse:

        1400177a0:
            ff 25 c2 94 00 00
            jmpq *0x94c2(%rip) # 0x140020c68

    Returns:

        {
            thunk_address: IAT_address
        }
    """

    thunks = {}

    lines = disassembly.splitlines()

    current_address = None

    for line in lines:

        m = re.match(
            r"^([0-9a-fA-F]+):\s+",
            line.strip()
        )

        if m:

            current_address = int(m.group(1), 16)

        if "jmpq" in line and "#" in line:

            m = re.search(
                r"#\s*0x([0-9a-fA-F]+)",
                line
            )

            if m and current_address is not None:

                iat = int(m.group(1), 16)

                thunks[current_address] = iat

    return thunks


# ============================================================
# FIND CALLS
# ============================================================

def find_api_calls(instructions, thunks, imports):
    """
    Resolve:

        CALL instruction
            |
            v
        Import thunk
            |
            v
        IAT address
            |
            v
        Imported API

    Example:

        callq 0x1400177a0
              |
              v
        thunk 0x1400177a0
              |
              v
        IAT 0x140020c68
              |
              v
        BCryptGenRandom
    """

    calls = []

    for ins in instructions:

        asm = ins["asm"].strip()

        # --------------------------------------------------
        # Recognize x86-64 call instructions.
        #
        # llvm-objdump uses "callq" for 64-bit calls.
        # --------------------------------------------------

        if not asm.startswith("callq"):
            continue

        # --------------------------------------------------
        # Extract the target address.
        #
        # Example:
        #
        # callq  0x1400177a0 <.text+0x167a0>
        #
        # We only need:
        #
        # 0x1400177a0
        # --------------------------------------------------

        match = re.search(
            r"callq\s+0x([0-9a-fA-F]+)",
            asm
        )

        if not match:
            continue

        target = int(
            match.group(1),
            16
        )

        # --------------------------------------------------
        # Is this CALL targeting one of our import thunks?
        # --------------------------------------------------

        if target not in thunks:
            continue

        # --------------------------------------------------
        # Resolve:
        #
        # thunk -> IAT
        # --------------------------------------------------

        iat = thunks[target]

        # --------------------------------------------------
        # Resolve:
        #
        # IAT -> imported API
        # --------------------------------------------------

        entry = imports.get(iat)

        if entry is None:
            continue

        # --------------------------------------------------
        # imports may contain either:
        #
        #   "BCryptGenRandom"
        #
        # or:
        #
        #   {
        #       "dll": "bcrypt.dll",
        #       "api": "BCryptGenRandom"
        #   }
        #
        # Handle both possibilities.
        # --------------------------------------------------

        if isinstance(entry, dict):

            dll = entry.get("dll", "")
            api = entry.get("api", "")

        elif isinstance(entry, tuple):

            if len(entry) >= 2:
                dll = entry[0]
                api = entry[1]
            else:
                dll = ""
                api = str(entry)

        else:

            dll = ""
            api = str(entry)

        calls.append({
            "address": ins["address"],
            "target": target,
            "iat": iat,
            "dll": dll,
            "api": api,
            "asm": asm
        })

    return calls


# ============================================================
# FUNCTION PROLOGUE ANALYSIS
# ============================================================

def calculate_function_frame_delta(instructions, function_start):

    """
    Calculate the stack-frame adjustment from a function's prologue.

    Scans the first ~20 instructions at function_start, looking for:
        pushq <register>      -> +8 bytes
        subq $IMM, %rsp       -> +IMM bytes

    Does NOT include the CALL instruction's implicit return-address push.

    Returns:
        Total prologue delta (in bytes), or 0 if function_start not found.
    """

    # --------------------------------------------------------
    # Find the instruction with address == function_start
    # --------------------------------------------------------

    start_index = None

    for i, ins in enumerate(instructions):

        if ins["address"] == function_start:

            start_index = i
            break

    if start_index is None:

        return 0

    # --------------------------------------------------------
    # Scan the first ~20 instructions from start
    # --------------------------------------------------------

    delta = 0

    for i in range(start_index, min(start_index + 20, len(instructions))):

        ins = instructions[i]

        asm = ins["asm"]

        # Remove comments
        asm = asm.split("#")[0].strip()

        if not asm:
            continue

        parts = asm.split(None, 1)

        if len(parts) < 1:
            continue

        mnemonic = parts[0].lower()

        operands = []

        if len(parts) == 2:

            operands = [
                x.strip()
                for x in parts[1].split(",")
            ]

        # ------------------------------------------------
        # Recognize: pushq <register>
        # ------------------------------------------------

        if mnemonic == "pushq":

            if len(operands) >= 1:

                reg = normalize_register(operands[0])

                if is_register(reg):

                    delta += 8
                    continue

            # If not a recognized pushq, stop prologue
            break

        # ------------------------------------------------
        # Recognize: subq $IMM, %rsp
        # ------------------------------------------------

        if mnemonic == "subq":

            if len(operands) == 2:

                src = operands[0]
                dst = operands[1]

                dst_reg = normalize_register(dst)

                if dst_reg == "RSP":

                    imm = parse_immediate(src)

                    if imm is not None and imm > 0:

                        delta += imm
                        continue

            # If not a recognized subq, stop prologue
            break

        # ------------------------------------------------
        # Any other instruction ends the prologue
        # ------------------------------------------------

        break

    return delta


# ============================================================
# FUNCTION CONTAINMENT
# ============================================================

def find_containing_function(instructions, target_address, function_starts):

    """
    Determine which function contains a given instruction address.

    Finds the largest function_start such that:
        function_start <= target_address

    Args:
        instructions: list of instruction dicts with 'address' field
        target_address: address to locate
        function_starts: collection of known function entry addresses

    Returns:
        Largest function_start <= target_address, or None if not found.
    """

    # --------------------------------------------------------
    # Filter to valid function starts
    # --------------------------------------------------------

    valid_starts = [
        addr for addr in function_starts
        if addr <= target_address
    ]

    if not valid_starts:

        return None

    # --------------------------------------------------------
    # Return the largest one
    # --------------------------------------------------------

    return max(valid_starts)


# ============================================================
# FIND DIRECT CALLER
# ============================================================

def find_direct_callers(instructions, target_function, function_starts):

    """
    Find direct callers of a target function.

    Scans all callq instructions, and for each one targeting target_function,
    identifies the caller function and call site.

    Args:
        instructions: list of instruction dicts with 'address' and 'asm'
        target_function: the function address being called
        function_starts: collection of known function entry addresses

    Returns:
        List of tuples: [(caller_function, call_site), ...]
        Returns empty list if no direct callers found.
    """

    callers = []

    # --------------------------------------------------------
    # Scan all instructions for direct callq
    # --------------------------------------------------------

    for ins in instructions:

        asm = ins["asm"].split("#")[0].strip()

        if not asm.startswith("callq"):

            continue

        # Extract target address from callq
        m = re.search(
            r"callq\s+0x([0-9a-fA-F]+)",
            asm
        )

        if not m:

            continue

        target = int(m.group(1), 16)

        # Check if this call targets our target_function
        if target != target_function:

            continue

        # Found a direct call to target_function
        call_site = ins["address"]

        # Find the function containing this call
        caller_func = find_containing_function(
            instructions,
            call_site,
            function_starts
        )

        if caller_func is not None:

            callers.append((caller_func, call_site))

    return callers


# ============================================================
# RSP MEMORY TRANSLATION
# ============================================================

def translate_rsp_memory_location(location, frame_delta):

    """
    Translate an RSP-relative memory location from a callee's frame
    back to the caller's pre-CALL frame.

    The calculation is:
        translated_offset = original_offset - frame_delta

    Args:
        location: Memory location string, e.g., "[RSP+0x1F0]"
        frame_delta: Stack frame delta (positive, in bytes)

    Returns:
        Translated location string, or None if not RSP-relative or malformed.

    Examples:
        translate_rsp_memory_location("[RSP+0x1F0]", 0x1D0) -> "[RSP+0x20]"
        translate_rsp_memory_location("[RSP+0x20]", 0x10)   -> "[RSP+0x10]"
        translate_rsp_memory_location("[RSP+0x10]", 0x20)   -> "[RSP-0x10]"
        translate_rsp_memory_location("[RAX+0x10]", 0x20)   -> None
    """

    location = location.strip()

    # --------------------------------------------------------
    # Match: [REGISTER+offset] or [REGISTER-offset] or [REGISTER]
    # --------------------------------------------------------

    m = re.match(
        r"^\[([A-Z0-9]+)(([+-])0x[0-9A-F]+)?\]$",
        location
    )

    if not m:

        return None

    reg_name = m.group(1)

    # --------------------------------------------------------
    # Only handle RSP
    # --------------------------------------------------------

    if reg_name != "RSP":

        return None

    # --------------------------------------------------------
    # Parse the offset
    # --------------------------------------------------------

    offset_str = m.group(2)

    if offset_str is None:

        # [RSP] -> offset is 0
        offset = 0

    else:

        # offset_str is something like "+0x1F0" or "-0x10"
        try:

            offset = int(offset_str.replace("+", ""), 16)

            if offset_str.startswith("-"):

                offset = -offset

        except ValueError:

            return None

    # --------------------------------------------------------
    # Translate: new_offset = offset - frame_delta
    # --------------------------------------------------------

    new_offset = offset - frame_delta

    # --------------------------------------------------------
    # Format the result
    # --------------------------------------------------------

    if new_offset == 0:

        return "[RSP]"

    elif new_offset > 0:

        return f"[RSP+0x{new_offset:X}]"

    else:

        return f"[RSP-0x{-new_offset:X}]"


# ============================================================
# SYMBOLIC ANALYSIS AROUND CALL
# ============================================================

def analyze_call(
    instructions,
    call_index,
    call,
    window=100,
    populate_caller=True
):

    state = SymbolicState()

    # --------------------------------------------------------
    # Calculate frame delta for the function containing this
    # call, so that RSP-relative memory lookups can be
    # translated to the caller's frame.
    # --------------------------------------------------------

    call_address = call.get("address")

    if call_address is not None:

        # Extract function entry points from CALL targets
        function_starts = set()

        for ins in instructions:

            asm = ins["asm"].split("#")[0].strip()

            if asm.startswith("callq"):

                m = re.search(
                    r"callq\s+0x([0-9a-fA-F]+)",
                    asm
                )

                if m:

                    function_starts.add(
                        int(m.group(1), 16)
                    )

        # Find the function containing this call
        containing_func = find_containing_function(
            instructions,
            call_address,
            function_starts
        )

        if containing_func is not None:

            prologue_delta = calculate_function_frame_delta(
                instructions,
                containing_func
            )

            # Total delta = prologue + CALL's implicit push
            state.frame_delta = prologue_delta + 8

            # ------------------------------------------------
            # Populate caller_state for cross-frame resolution
            # (only if populate_caller=True to prevent infinite
            # recursion)
            # ------------------------------------------------

            if populate_caller:

                callers = find_direct_callers(
                    instructions,
                    containing_func,
                    function_starts
                )

                if callers:

                    caller_func, caller_call_site = callers[0]

                    # Find the index of the caller's CALL instruction
                    caller_call_index = None

                    for idx, ins in enumerate(instructions):

                        if ins.get("address") == caller_call_site:

                            caller_call_index = idx
                            break

                    if caller_call_index is not None:

                        # Create a dummy call dict for the caller analysis
                        caller_call_dict = {
                            "address": caller_call_site,
                            "api": f"CALLER_OF_0x{containing_func:X}"
                        }

                        # Analyze the caller's state at its CALL site
                        # Pass populate_caller=False to prevent infinite recursion
                        state.caller_state = analyze_call(
                            instructions,
                            caller_call_index,
                            caller_call_dict,
                            window=100,
                            populate_caller=False
                        )

    start = max(
        0,
        call_index - window
    )

    end = call_index

    for i in range(start, end):

        process_instruction(
            instructions[i],
            state
        )

    print("\nPRE-CALL SYMBOLIC STATE")
    print("-" * 70)

    state.dump_registers()

    state.dump_provenance()

    print("\nMEMORY STATE")
    print("-" * 70)

    if state.memory:

        for location, value in state.memory.items():

            print(
                f"{location:<15}= {value}"
            )

    else:

        print("No tracked memory values.")

    return state

# ============================================================
# RNG API SEMANTIC ANALYSIS
# ============================================================

def analyze_rng_api(call, state):
    """
    Interpret arguments for supported RNG APIs.

    Currently supported:
        BCryptGenRandom

    Windows x64 calling convention:

        RCX = argument 1
        RDX = argument 2
        R8  = argument 3
        R9  = argument 4

    BCryptGenRandom signature:

        BCryptGenRandom(
            BCRYPT_ALG_HANDLE hAlgorithm,
            PUCHAR            pbBuffer,
            ULONG             cbBuffer,
            ULONG             dwFlags
        );
    """

    api = call.get("api", "")

    if api != "BCryptGenRandom":
        return

    # --------------------------------------------------------
    # Read the symbolic values produced by our existing
    # instruction analysis.
    # --------------------------------------------------------

    h_algorithm = state.get_reg("RCX")
    buffer_ptr = state.get_reg("RDX")
    buffer_size = state.get_reg("R8")
    flags = state.get_reg("R9")

    print()
    print("=" * 70)
    print("BCryptGenRandom ARGUMENT ANALYSIS")
    print("=" * 70)

    print()
    print(f"CALL SITE        : 0x{call['address']:x}")

    print()
    print("Windows x64 arguments")
    print("-" * 70)

    print(f"RCX / hAlgorithm : {h_algorithm}")
    print(f"RDX / pbBuffer   : {buffer_ptr}")
    print(f"R8  / cbBuffer   : {buffer_size}")
    print(f"R9  / dwFlags    : {flags}")

    # --------------------------------------------------------
    # Interpret the known values.
    # --------------------------------------------------------

    print()
    print("Interpretation")
    print("-" * 70)

    if h_algorithm == "0":
        print("Algorithm handle : NULL")
        print("RNG selection    : System-preferred RNG")
    else:
        print(f"Algorithm handle : {h_algorithm}")

    print(f"Output buffer    : {buffer_ptr}")
    print(f"Output size      : {buffer_size} bytes")
    print(f"Flags            : {flags}")

# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) != 2:

        print(
            "Usage: python binary_argument_analyzer.py <binary>"
        )

        sys.exit(1)

    binary = sys.argv[1]

    print("=" * 70)
    print("BINARY ARGUMENT / REGISTER ANALYZER")
    print("=" * 70)

    print()
    print(f"File: {binary}")

    # ========================================================
    # STEP 1: DISASSEMBLY
    # ========================================================

    print("\nReading disassembly...")

    disassembly = get_disassembly(binary)

    instructions = parse_instructions(
        disassembly
    )

    print(
        f"Instructions parsed: {len(instructions)}"
    )

    # ========================================================
    # STEP 2: PE IMPORTS
    # ========================================================

    print("\nReading PE imports...")

    imports = parse_imports(binary)

    print(
        f"Import entries parsed: {len(imports)}"
    )

    # ========================================================
    # STEP 3: FIND IMPORT THUNKS
    # ========================================================

    print("\nFinding import thunks...")

    thunks = find_thunks(
        disassembly
    )

    print(
        f"Import thunks found: {len(thunks)}"
    )

    # ========================================================
    # STEP 4: FIND ALL API CALLS
    # ========================================================

    calls = find_api_calls(
        instructions,
        thunks,
        imports
    )

    print()
    print("=" * 70)
    print("DEBUG: CALL PARSER")
    print("=" * 70)

    print(f"Total instructions : {len(instructions)}")
    print(f"Total calls        : {len(calls)}")

    print()
    print("Sample instructions:")

    for ins in instructions[:20]:
        print(ins)

    # ========================================================
    # STEP 5: FILTER TARGET APIs
    # ========================================================

    target_calls = [
        c for c in calls
        if c["api"] in TARGET_APIS
    ]

    # Map instruction address -> instruction index.
    #
    # This is important because analyze_call() works using
    # the instruction index immediately before the API call.
    address_to_index = {
        ins["address"]: i
        for i, ins in enumerate(instructions)
    }

    # ========================================================
    # DEBUG 1:
    # SHOW FIRST CALL TARGETS
    # ========================================================

    print()
    print("=" * 70)
    print("DEBUG: FIRST CALL TARGETS")
    print("=" * 70)

    for call in calls[:30]:

        print(
            f"CALL 0x{call['address']:x} "
            f"TARGET 0x{call['target']:x}"
        )

    # ========================================================
    # DEBUG 2:
    # SHOW IMPORT THUNK ADDRESSES
    # ========================================================

    print()
    print("=" * 70)
    print("DEBUG: IMPORT THUNK ADDRESSES")
    print("=" * 70)

    for thunk, iat in thunks.items():

        print(
            f"THUNK 0x{thunk:x} "
            f"-> IAT 0x{iat:x}"
        )

    # ========================================================
    # DEBUG 3:
    # CALL -> THUNK -> IAT -> API
    # ========================================================

    print()
    print("=" * 70)
    print("DEBUG: CALL -> THUNK -> IAT -> API")
    print("=" * 70)

    for call in calls:

        target = call["target"]

        if target in thunks:

            iat = thunks[target]

            entry = imports.get(iat)

            print(
                f"CALL 0x{call['address']:x} "
                f"-> THUNK 0x{target:x} "
                f"-> IAT 0x{iat:x} "
                f"-> {entry}"
            )

    # ========================================================
    # DEBUG 4:
    # FUNCTION FRAME DELTA
    # ========================================================

    frame_delta = calculate_function_frame_delta(
        instructions,
        0x140001040
    )

    print()
    print("=" * 70)
    print("DEBUG: FUNCTION FRAME")
    print("=" * 70)
    print("Function       : 0x140001040")
    print(f"Frame delta    : 0x{frame_delta:X}")


    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print(
        f"Target API calls found: "
        f"{len(target_calls)}"
    )

    # ========================================================
    # TARGET API CALL SITES
    # ========================================================

    print()
    print("=" * 70)
    print("TARGET API CALL SITES")
    print("=" * 70)

    if not target_calls:

        print()
        print("No target API calls found.")

    else:

        for call in target_calls:

            target = call["target"]

            iat = thunks.get(target)

            print()
            print(
                f"CALL SITE : "
                f"0x{call['address']:x}"
            )

            print(
                f"TARGET    : "
                f"0x{target:x}"
            )

            if iat is not None:

                print(
                    f"IAT       : "
                    f"0x{iat:x}"
                )

            print(
                f"DLL       : "
                f"{call.get('dll', 'UNKNOWN')}"
            )

            print(
                f"API       : "
                f"{call['api']}"
            )

    # ========================================================
    # RNG API CALL SITES
    # ========================================================

    rng_calls = [
        c for c in target_calls
        if c["api"] in RNG_APIS
    ]

    print()
    print("=" * 70)
    print("DETECTED RNG API CALL SITES")
    print("=" * 70)

    if not rng_calls:

        print()
        print("No RNG API call sites found.")

    else:

        for call in rng_calls:

            target = call["target"]

            iat = thunks.get(target)

            print()

            print(
                f"CALL SITE     : "
                f"0x{call['address']:x}"
            )

            print(
                f"IMPORT THUNK  : "
                f"0x{target:x}"
            )

            if iat is not None:

                print(
                    f"IAT ADDRESS   : "
                    f"0x{iat:x}"
                )

            print(
                f"DLL           : "
                f"{call.get('dll', 'UNKNOWN')}"
            )

            print(
                f"API           : "
                f"{call['api']}"
            )

            print(
                "Classification: "
                "OS cryptographic RNG"
            )

    # ========================================================
    # CRYPTOGRAPHIC API CALL SITES
    # ========================================================

    crypto_calls = [
        c for c in target_calls
        if c["api"] in CRYPTO_APIS
    ]

    print()
    print("=" * 70)
    print("DETECTED CRYPTOGRAPHIC API CALL SITES")
    print("=" * 70)

    if not crypto_calls:

        print()
        print(
            "No target cryptographic API calls found."
        )

    else:

        for call in crypto_calls:

            target = call["target"]

            iat = thunks.get(target)

            print()

            print(
                f"CALL SITE     : "
                f"0x{call['address']:x}"
            )

            print(
                f"IMPORT THUNK  : "
                f"0x{target:x}"
            )

            if iat is not None:

                print(
                    f"IAT ADDRESS   : "
                    f"0x{iat:x}"
                )

            print(
                f"DLL           : "
                f"{call.get('dll', 'UNKNOWN')}"
            )

            print(
                f"API           : "
                f"{call['api']}"
            )

            api = call["api"]

            if api == "BCryptOpenAlgorithmProvider":

                classification = (
                    "Windows CNG algorithm API"
                )

            elif api == "BCryptSetProperty":

                classification = (
                    "Windows CNG property API"
                )

            elif api == "BCryptGetProperty":

                classification = (
                    "Windows CNG property API"
                )

            elif api == "BCryptGenerateSymmetricKey":

                classification = (
                    "Windows CNG symmetric-key API"
                )

            elif api == "BCryptEncrypt":

                classification = (
                    "Windows CNG encryption API"
                )

            elif api == "BCryptDestroyKey":

                classification = (
                    "Windows CNG key-management API"
                )

            elif api == "BCryptCloseAlgorithmProvider":

                classification = (
                    "Windows CNG provider-management API"
                )

            else:

                classification = (
                    "Cryptographic API"
                )

            print(
                f"Classification: "
                f"{classification}"
            )

    # ========================================================
    # STEP 6: ARGUMENT / REGISTER ANALYSIS
    # ========================================================
    #
    # Now that API call resolution is working, perform
    # symbolic backward analysis immediately before each
    # target API call.
    #
    # Windows x64 API arguments:
    #
    #     RCX = argument 1
    #     RDX = argument 2
    #     R8  = argument 3
    #     R9  = argument 4
    #
    # We currently track simple MOV/XOR/LEA operations and
    # stack-backed values.
    # ========================================================

    print()
    print("=" * 70)
    print("ARGUMENT / REGISTER ANALYSIS")
    print("=" * 70)

    if not target_calls:

        print()
        print("No target API calls to analyze.")

    else:

        for call in target_calls:

            call_address = call["address"]

            call_index = address_to_index.get(
                call_address
            )

            print()
            print("=" * 70)
            print(
                f"API: {call['api']}"
            )
            print(
                f"CALL SITE: 0x{call_address:x}"
            )
            print("=" * 70)

            if call_index is None:

                print(
                    "ERROR: Could not locate call "
                    "instruction in parsed disassembly."
                )

                continue

            # ------------------------------------------------
            # Perform symbolic backward analysis.
            #
            # analyze_call() examines the instructions before
            # the CALL and prints the symbolic register state.
            # ------------------------------------------------

            state = analyze_call(
                instructions,
                call_index,
                call,
                window=100
            )

            # ------------------------------------------------
            # Explicit Windows x64 argument summary.
            # ------------------------------------------------

            print()
            print("WINDOWS x64 ARGUMENTS")
            print("-" * 70)

            print(
                f"ARG1 / RCX = {state.get_reg('RCX')}"
            )

            print(
                f"ARG2 / RDX = {state.get_reg('RDX')}"
            )

            print(
                f"ARG3 / R8  = {state.get_reg('R8')}"
            )

            print(
                f"ARG4 / R9  = {state.get_reg('R9')}"
            )

            # ------------------------------------------------
            # API-specific semantic analysis.
            #
            # For BCryptGenRandom this interprets:
            #
            # RCX -> hAlgorithm
            # RDX -> pbBuffer
            # R8  -> cbBuffer
            # R9  -> dwFlags
            # ------------------------------------------------

            analyze_rng_api(
                call,
                state
            )


    # ========================================================
    # COMPLETE
    # ========================================================

    print()
    print("=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":
    main()