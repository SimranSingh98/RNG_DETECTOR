import re
import sys


# ============================================================
# RNG CLASSIFICATION
# ============================================================

RNG_RULES = {
    "BCryptGenRandom": {
        "type": "OS cryptographic RNG",
        "security": "GOOD"
    },

    "getrandom": {
        "type": "OS randomness source",
        "security": "GOOD"
    },

    "RAND_bytes": {
        "type": "Cryptographic library RNG",
        "security": "GOOD"
    },

    "RAND_priv_bytes": {
        "type": "Cryptographic library RNG",
        "security": "GOOD"
    },

    "rand": {
        "type": "Non-cryptographic PRNG",
        "security": "BAD"
    },

    "random": {
        "type": "Non-cryptographic PRNG",
        "security": "BAD"
    }
}


# ============================================================
# FIND RNG → DESTINATION DATA FLOW
# ============================================================

def detect_rng_data_flow(source):

    flows = []

    # --------------------------------------------------------
    # Pattern 1:
    #
    # BCryptGenRandom(NULL, iv, 16, ...)
    #
    # Meaning:
    #
    #       BCryptGenRandom
    #              |
    #              v
    #             iv
    # --------------------------------------------------------

    pattern = (
        r'\bBCryptGenRandom\s*\('
        r'\s*NULL\s*,'
        r'\s*(\w+)\s*,'
    )

    matches = re.finditer(pattern, source)

    for match in matches:

        destination = match.group(1)

        flows.append({
            "rng": "BCryptGenRandom",
            "destination": destination,
            "type": RNG_RULES["BCryptGenRandom"]["type"],
            "security": RNG_RULES["BCryptGenRandom"]["security"]
        })


    # --------------------------------------------------------
    # Pattern:
    #
    #     iv[i] = rand();
    #
    # or:
    #
    #     iv[i] = (uint8_t)(rand() & 0xFF);
    #
    # or similar simple expressions containing rand().
    # --------------------------------------------------------

    pattern = (
        r'\b(\w+)\s*\[[^\]]+\]\s*='
        r'[^;]*\brand\s*\('
    )

    matches = re.finditer(pattern, source)

    for match in matches:

        destination = match.group(1)

        flows.append({
            "rng": "rand",
            "destination": destination,
            "type": RNG_RULES["rand"]["type"],
            "security": RNG_RULES["rand"]["security"]
        })

    return flows


# ============================================================
# FIND AES-CBC USAGE
# ============================================================

def detect_aes_cbc_usage(source):

    pattern = r'\baes_cbc_encrypt\s*\('

    return bool(re.search(pattern, source))


# ============================================================
# DETERMINE WHETHER RNG DESTINATION REACHES AES-CBC
# ============================================================

def check_rng_to_aes_flow(source, destination):

    # We are intentionally using a simple pattern for V2.
    #
    # We want to detect:
    #
    #     aes_cbc_encrypt(key, destination, ...)
    #
    # Therefore destination must appear as the second
    # argument.

    pattern = (
        r'\baes_cbc_encrypt\s*\('
        r'\s*[^,]+,\s*'
        + re.escape(destination)
        + r'\s*,'
    )

    return bool(re.search(pattern, source, re.DOTALL))


# ============================================================
# ANALYZE SOURCE
# ============================================================

def analyze_source(filename):

    with open(filename, "r", encoding="utf-8") as f:
        source = f.read()


    print("=" * 65)
    print("CRYPTOGRAPHIC RNG SECURITY ANALYZER")
    print("=" * 65)

    print(f"File: {filename}")
    print()


    # --------------------------------------------------------
    # Step 1: Detect AES-CBC
    # --------------------------------------------------------

    aes_cbc_found = detect_aes_cbc_usage(source)

    if aes_cbc_found:

        print("Cryptographic operation:")
        print("    AES-CBC")
        print()

    else:

        print("Cryptographic operation:")
        print("    NOT DETECTED")
        print()


    # --------------------------------------------------------
    # Step 2: Detect RNG → destination
    # --------------------------------------------------------

    flows = detect_rng_data_flow(source)

    if not flows:

        print("RNG data flow:")
        print("    NOT DETECTED")
        print()

        print("RESULT: REVIEW")
        print("=" * 65)

        return


    print("Detected RNG data flow(s):")
    print()


    final_status = "PASS"


    for flow in flows:

        rng = flow["rng"]
        destination = flow["destination"]

        print(f"RNG source:")
        print(f"    {rng}()")

        print(f"Classification:")
        print(f"    {flow['type']}")

        print(f"RNG destination:")
        print(f"    {destination}")

        print()


        # ----------------------------------------------------
        # Check whether destination reaches AES-CBC
        # ----------------------------------------------------

        reaches_aes = check_rng_to_aes_flow(
            source,
            destination
        )


        if reaches_aes:

            print("Data flow:")
            print(f"    {rng}()")
            print("       |")
            print("       v")
            print(f"    {destination}")
            print("       |")
            print("       v")
            print("    AES-CBC")

        else:

            print("Data flow:")
            print(f"    {rng}()")
            print("       |")
            print("       v")
            print(f"    {destination}")
            print("       |")
            print("       X")
            print("    AES-CBC relationship NOT confirmed")

        print()


        # ----------------------------------------------------
        # Security decision
        # ----------------------------------------------------

        if flow["security"] == "BAD" and reaches_aes:

            print("Security finding:")
            print(
                "    Non-cryptographic RNG is used "
                "for AES-CBC input."
            )

            print()

            final_status = "FLAG"


        elif flow["security"] == "GOOD" and reaches_aes:

            print("Security finding:")
            print(
                "    Recognized cryptographic/OS RNG "
                "feeds AES-CBC input."
            )

            print()

        else:

            print("Security finding:")
            print(
                "    RNG usage requires further review."
            )

            print()

            if final_status != "FLAG":
                final_status = "REVIEW"


    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    print("-" * 65)

    print(f"FINAL RESULT: {final_status}")

    print("=" * 65)


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python rng_source_analyzer.py <source.c>"
        )

        sys.exit(1)


    analyze_source(sys.argv[1])