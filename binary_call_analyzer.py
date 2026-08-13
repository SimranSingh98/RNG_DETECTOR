import sys
import re
import subprocess


# ============================================================
# Configuration
# ============================================================

IMAGE_BASE = 0x140000000

RNG_APIS = {
    "BCryptGenRandom": "OS cryptographic RNG",
    "CryptGenRandom": "OS cryptographic RNG",
    "BCryptGenRandomEx": "OS cryptographic RNG",
    "RtlGenRandom": "OS cryptographic RNG",
    "SystemFunction036": "OS cryptographic RNG",

    # Non-cryptographic RNGs
    "rand": "Non-cryptographic PRNG",
    "srand": "Non-cryptographic PRNG",
    "random": "Non-cryptographic PRNG",
}

CRYPTO_APIS = {
    "BCryptEncrypt": "Windows CNG encryption API",
    "BCryptDecrypt": "Windows CNG decryption API",
    "BCryptGenerateSymmetricKey": "Windows CNG symmetric-key API",
    "BCryptOpenAlgorithmProvider": "Windows CNG algorithm API",
    "BCryptSetProperty": "Windows CNG property API",
    "BCryptGetProperty": "Windows CNG property API",

    "BCryptSignHash": "Windows CNG signing API",
    "BCryptVerifySignature": "Windows CNG signature verification API",

    "CryptEncrypt": "Windows CryptoAPI encryption API",
    "CryptDecrypt": "Windows CryptoAPI decryption API",

    "EVP_EncryptInit_ex": "OpenSSL encryption API",
    "EVP_EncryptUpdate": "OpenSSL encryption API",
    "EVP_EncryptFinal_ex": "OpenSSL encryption API",

    "EVP_DecryptInit_ex": "OpenSSL decryption API",
    "EVP_DecryptUpdate": "OpenSSL decryption API",
    "EVP_DecryptFinal_ex": "OpenSSL decryption API",
}


# ============================================================
# Run llvm-objdump
# ============================================================

def run_objdump(args):

    try:

        result = subprocess.run(
            ["llvm-objdump"] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace"
        )

        if result.returncode != 0:

            print("ERROR running llvm-objdump")
            print(result.stderr)

            sys.exit(1)

        return result.stdout

    except FileNotFoundError:

        print(
            "ERROR: llvm-objdump was not found in PATH."
        )

        sys.exit(1)


# ============================================================
# Convert RVA to virtual address
# ============================================================

def rva_to_va(rva):

    return IMAGE_BASE + rva


# ============================================================
# Parse PE import table
# ============================================================

def parse_imports(output):

    """
    Parse llvm-objdump -p output.

    Example input:

        lookup 000209c8 time 00000000 fwd 00000000
        name 000214bc addr 00020c50

            DLL Name: bcrypt.dll
            Hint/Ord  Name
                   2  BCryptCloseAlgorithmProvider
                  15  BCryptDestroyKey
                  20  BCryptEncrypt
                  31  BCryptGenRandom
                  33  BCryptGenerateSymmetricKey

    Important:

    The "addr" line appears BEFORE the "DLL Name" line.

    Therefore we first save the pending IAT RVA and then
    associate it with the DLL when DLL Name appears.
    """

    imports = {}

    pending_iat_rva = None
    current_iat_va = None
    current_dll = None

    lines = output.splitlines()

    for line in lines:

        # ----------------------------------------------------
        # Example:
        #
        # name 000214bc addr 00020c50
        # ----------------------------------------------------

        addr_match = re.search(
            r"\baddr\s+([0-9a-fA-F]+)",
            line
        )

        if addr_match:

            pending_iat_rva = int(
                addr_match.group(1),
                16
            )

            continue

        # ----------------------------------------------------
        # Example:
        #
        # DLL Name: bcrypt.dll
        # ----------------------------------------------------

        dll_match = re.search(
            r"DLL Name:\s*(.+)",
            line,
            re.IGNORECASE
        )

        if dll_match:

            current_dll = dll_match.group(1).strip()

            if pending_iat_rva is not None:

                current_iat_va = rva_to_va(
                    pending_iat_rva
                )

            continue

        # ----------------------------------------------------
        # Example:
        #
        #       20  BCryptEncrypt
        #       31  BCryptGenRandom
        #
        # The first number is the hint/ordinal.
        # ----------------------------------------------------

        api_match = re.match(
            r"^\s*\d+\s+([A-Za-z_][A-Za-z0-9_]*)\s*$",
            line
        )

        if api_match and current_iat_va is not None:

            api = api_match.group(1)

            imports[current_iat_va] = {
                "api": api,
                "dll": current_dll
            }

            # x64 PE IAT entries are 8 bytes.
            current_iat_va += 8

    return imports


# ============================================================
# Parse import thunks
# ============================================================

def parse_thunks(disassembly):

    """
    Parse instructions such as:

        140017790:
            ff 25 ca 94 00 00
            jmpq *0x94ca(%rip) # 0x140020c60

    This gives:

        thunk = 0x140017790
        IAT   = 0x140020c60
    """

    thunks = {}

    for line in disassembly.splitlines():

        # ----------------------------------------------------
        # Match:
        #
        # 140017790: ff 25 ca 94 00 00
        # jmpq *0x94ca(%rip) # 0x140020c60
        # ----------------------------------------------------

        match = re.search(
            r"^\s*([0-9a-fA-F]+):.*?"
            r"jmpq\s+\*.*?#\s*"
            r"(0x[0-9a-fA-F]+)",
            line
        )

        if not match:
            continue

        thunk = int(
            match.group(1),
            16
        )

        iat = int(
            match.group(2),
            16
        )

        thunks[thunk] = iat

    return thunks


# ============================================================
# Parse direct CALL instructions
# ============================================================

def parse_calls(disassembly):

    """
    Find direct CALL instructions.

    Example:

        14000101e:
            e8 7d 67 01 00
            callq 0x1400177a0

    Result:

        call_site = 0x14000101e
        target    = 0x1400177a0
    """

    calls = []

    for line in disassembly.splitlines():

        match = re.search(
            r"^\s*([0-9a-fA-F]+):.*?"
            r"callq?\s+"
            r"(0x[0-9a-fA-F]+)",
            line
        )

        if not match:
            continue

        call_site = int(
            match.group(1),
            16
        )

        target = int(
            match.group(2),
            16
        )

        calls.append({
            "call_site": call_site,
            "target": target
        })

    return calls


# ============================================================
# Resolve API calls
# ============================================================

def resolve_api_calls(
    calls,
    thunks,
    imports
):

    resolved = []

    for call in calls:

        call_site = call["call_site"]
        target = call["target"]

        # ----------------------------------------------------
        # Direct call to an import thunk
        # ----------------------------------------------------

        if target not in thunks:
            continue

        iat = thunks[target]

        # ----------------------------------------------------
        # IAT address -> imported API
        # ----------------------------------------------------

        if iat not in imports:
            continue

        api_info = imports[iat]

        resolved.append({
            "call_site": call_site,
            "target": target,
            "iat": iat,
            "api": api_info["api"],
            "dll": api_info["dll"]
        })

    return resolved


# ============================================================
# Print import table
# ============================================================

def print_imports(imports):

    print()
    print("=" * 70)
    print("DEBUG: IMPORT MAPPINGS")
    print("=" * 70)

    for iat in sorted(imports):

        info = imports[iat]

        print(
            f"0x{iat:x} -> "
            f"{info['dll']} -> "
            f"{info['api']}"
        )


# ============================================================
# Print all resolved API calls
# ============================================================

def print_resolved_calls(resolved):

    print()
    print("=" * 70)
    print("ALL RESOLVED API CALL SITES")
    print("=" * 70)

    if not resolved:

        print()
        print("No resolved imported API calls found.")
        return

    for item in resolved:

        print()
        print(
            f"CALL SITE : 0x{item['call_site']:x}"
        )

        print(
            f"TARGET    : 0x{item['target']:x}"
        )

        print(
            f"IAT       : 0x{item['iat']:x}"
        )

        print(
            f"DLL       : {item['dll']}"
        )

        print(
            f"API       : {item['api']}"
        )


# ============================================================
# Print cryptographic API calls
# ============================================================

def print_crypto_calls(resolved):

    print()
    print("=" * 70)
    print("DETECTED CRYPTOGRAPHIC API CALL SITES")
    print("=" * 70)

    crypto_found = []

    for item in resolved:

        api = item["api"]

        if api in CRYPTO_APIS:

            crypto_found.append(item)

    if not crypto_found:

        print()
        print("No target cryptographic API calls found.")
        return

    for item in crypto_found:

        api = item["api"]

        print()
        print(
            f"CALL SITE     : "
            f"0x{item['call_site']:x}"
        )

        print(
            f"IMPORT THUNK  : "
            f"0x{item['target']:x}"
        )

        print(
            f"IAT ADDRESS   : "
            f"0x{item['iat']:x}"
        )

        print(
            f"DLL           : "
            f"{item['dll']}"
        )

        print(
            f"API           : "
            f"{api}"
        )

        print(
            f"Classification: "
            f"{CRYPTO_APIS[api]}"
        )


# ============================================================
# Print RNG API calls
# ============================================================

def print_rng_calls(resolved):

    print()
    print("=" * 70)
    print("DETECTED RNG API CALL SITES")
    print("=" * 70)

    rng_found = []

    for item in resolved:

        api = item["api"]

        if api in RNG_APIS:

            rng_found.append(item)

    if not rng_found:

        print()
        print("No RNG API calls found.")
        return

    for item in rng_found:

        api = item["api"]

        print()
        print(
            f"CALL SITE     : "
            f"0x{item['call_site']:x}"
        )

        print(
            f"IMPORT THUNK  : "
            f"0x{item['target']:x}"
        )

        print(
            f"IAT ADDRESS   : "
            f"0x{item['iat']:x}"
        )

        print(
            f"DLL           : "
            f"{item['dll']}"
        )

        print(
            f"API           : "
            f"{api}"
        )

        print(
            f"Classification: "
            f"{RNG_APIS[api]}"
        )


# ============================================================
# Main
# ============================================================

def main():

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "    python binary_call_analyzer.py <exe>"
        )

        print()

        print(
            "Example:"
        )

        print(
            "    python binary_call_analyzer.py "
            "good_real_Od.exe"
        )

        sys.exit(1)

    filename = sys.argv[1]

    print("=" * 70)
    print("BINARY CRYPTOGRAPHIC CALL-SITE ANALYSIS")
    print("=" * 70)

    print()
    print(
        f"File: {filename}"
    )

    # --------------------------------------------------------
    # Get import table
    # --------------------------------------------------------

    print()
    print(
        "Parsing PE import table..."
    )

    imports_output = run_objdump([
        "-p",
        filename
    ])

    imports = parse_imports(
        imports_output
    )

    # --------------------------------------------------------
    # Get disassembly
    # --------------------------------------------------------

    print(
        "Parsing disassembly..."
    )

    disassembly = run_objdump([
        "-d",
        filename
    ])

    # --------------------------------------------------------
    # Parse import thunks
    # --------------------------------------------------------

    thunks = parse_thunks(
        disassembly
    )

    # --------------------------------------------------------
    # Parse direct calls
    # --------------------------------------------------------

    calls = parse_calls(
        disassembly
    )

    # --------------------------------------------------------
    # Resolve calls
    # --------------------------------------------------------

    resolved = resolve_api_calls(
        calls,
        thunks,
        imports
    )

    # --------------------------------------------------------
    # Debug information
    # --------------------------------------------------------

    print_imports(
        imports
    )

    print()
    print(
        f"Import entries parsed : {len(imports)}"
    )

    print(
        f"Import thunks found    : {len(thunks)}"
    )

    print(
        f"CALL instructions      : {len(calls)}"
    )

    print(
        f"Resolved API calls     : {len(resolved)}"
    )

    # --------------------------------------------------------
    # Show all resolved APIs
    # --------------------------------------------------------

    print_resolved_calls(
        resolved
    )

    # --------------------------------------------------------
    # RNG analysis
    # --------------------------------------------------------

    print_rng_calls(
        resolved
    )

    # --------------------------------------------------------
    # Crypto analysis
    # --------------------------------------------------------

    print_crypto_calls(
        resolved
    )

    print()
    print("=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":

    main()