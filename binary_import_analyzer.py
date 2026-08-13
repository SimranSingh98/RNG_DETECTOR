import subprocess
import sys
import re


RNG_APIS = {
    "BCryptGenRandom": "OS cryptographic RNG",
    "RtlGenRandom": "OS cryptographic RNG",
    "CryptGenRandom": "OS cryptographic RNG",
    "getrandom": "OS randomness source",
    "arc4random": "OS randomness source",
    "rand": "Non-cryptographic PRNG",
    "srand": "Non-cryptographic PRNG",
}


CRYPTO_APIS = {
    "BCryptEncrypt": "Windows CNG encryption API",
    "BCryptDecrypt": "Windows CNG decryption API",
    "BCryptGenerateSymmetricKey": "Windows CNG symmetric-key API",
    "BCryptOpenAlgorithmProvider": "Windows CNG algorithm API",
}


def get_objdump_output(binary):

    result = subprocess.run(
        ["llvm-objdump", "-p", binary],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        print("Failed to analyze binary.")
        sys.exit(1)

    return result.stdout


def extract_imports(output):

    imports = set()

    inside_import_table = False

    for line in output.splitlines():

        if "The Import Tables:" in line:
            inside_import_table = True
            continue

        if not inside_import_table:
            continue

        # Example:
        #
        #          20  BCryptEncrypt
        #          31  BCryptGenRandom
        #
        match = re.match(
            r"^\s*\d+\s+([A-Za-z_][A-Za-z0-9_]*)\s*$",
            line
        )

        if match:
            imports.add(match.group(1))

    return imports


def analyze(binary):

    output = get_objdump_output(binary)

    imports = extract_imports(output)

    print("=" * 70)
    print("BINARY CRYPTOGRAPHIC API ANALYSIS")
    print("=" * 70)

    print(f"\nFile: {binary}")

    print("\nImported APIs")
    print("-" * 70)

    for api in sorted(imports):
        print(f"    {api}")

    rng_found = []
    crypto_found = []

    for api, classification in RNG_APIS.items():

        if api in imports:
            rng_found.append((api, classification))

    for api, classification in CRYPTO_APIS.items():

        if api in imports:
            crypto_found.append((api, classification))

    print("\nDetected RNG APIs")
    print("-" * 70)

    if rng_found:

        for api, classification in rng_found:

            print(f"\n    RNG API          : {api}")
            print(f"    Classification  : {classification}")

    else:
        print("    None detected.")

    print("\nDetected Cryptographic APIs")
    print("-" * 70)

    if crypto_found:

        for api, classification in crypto_found:

            print(f"\n    Crypto API       : {api}")
            print(f"    Classification  : {classification}")

    else:
        print("    None detected.")

    print("\n" + "=" * 70)


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print("Usage:")
        print("    python binary_import_analyzer.py <binary.exe>")
        sys.exit(1)

    analyze(sys.argv[1])