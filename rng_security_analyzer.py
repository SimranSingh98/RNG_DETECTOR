import json
import sys


# ============================================================
# RNG DATABASE
# ============================================================

RNG_DATABASE = {

    "BCryptGenRandom": {
        "classification": "OS cryptographic RNG",
        "security": "GOOD",
        "mode": "BUFFER_WRITE"
    },

    "getrandom": {
        "classification": "OS randomness source",
        "security": "GOOD",
        "mode": "BUFFER_WRITE"
    },

    "RAND_bytes": {
        "classification": "Cryptographic library RNG",
        "security": "GOOD",
        "mode": "BUFFER_WRITE"
    },

    "RAND_priv_bytes": {
        "classification": "Cryptographic library RNG",
        "security": "GOOD",
        "mode": "BUFFER_WRITE"
    },

    "rand": {
        "classification": "Non-cryptographic PRNG",
        "security": "BAD",
        "mode": "RETURN_VALUE"
    },

    "random": {
        "classification": "Non-cryptographic PRNG",
        "security": "BAD",
        "mode": "RETURN_VALUE"
    }
}


# ============================================================
# CRYPTO DATABASE
# ============================================================

CRYPTO_DATABASE = {

    "aes_cbc_encrypt": {
        "algorithm": "AES-CBC",

        # CallExpr child 0 = function
        # child 1 = key
        # child 2 = IV
        "iv_argument": 2
    }
}


# ============================================================
# LOAD AST JSON
# ============================================================

def load_json(filename):

    with open(filename, "rb") as f:
        data = f.read()

    if data.startswith(b"\xff\xfe"):
        text = data.decode("utf-16")

    elif data.startswith(b"\xfe\xff"):
        text = data.decode("utf-16")

    elif data.startswith(b"\xef\xbb\xbf"):
        text = data.decode("utf-8-sig")

    else:
        text = data.decode("utf-8")

    return json.loads(text)


# ============================================================
# AST HELPERS
# ============================================================

def get_referenced_decl(node):

    if not isinstance(node, dict):
        return None

    ref = node.get("referencedDecl")

    if isinstance(ref, dict):
        return ref

    return None


def find_referenced_decl(node):

    if not isinstance(node, dict):
        return None

    ref = get_referenced_decl(node)

    if ref:
        return ref

    for child in node.get("inner", []):

        ref = find_referenced_decl(child)

        if ref:
            return ref

    return None


def find_function_name(call_node):

    for child in call_node.get("inner", []):

        ref = find_referenced_decl(child)

        if ref and ref.get("kind") == "FunctionDecl":
            return ref.get("name")

    return None


def extract_declref_name(node):

    if not isinstance(node, dict):
        return None

    if node.get("kind") == "DeclRefExpr":

        ref = node.get("referencedDecl")

        if isinstance(ref, dict):
            return ref.get("name")

    for child in node.get("inner", []):

        name = extract_declref_name(child)

        if name:
            return name

    return None


def extract_integer(node):

    if not isinstance(node, dict):
        return None

    if node.get("kind") == "IntegerLiteral":

        value = node.get("value")

        if value is not None:
            return int(value)

    for child in node.get("inner", []):

        value = extract_integer(child)

        if value is not None:
            return value

    return None


# ============================================================
# FIND RNG CALL INSIDE AN EXPRESSION
# ============================================================

def find_rng_call(node):

    """
    Recursively search an expression for a recognized RNG call.

    Example:

        CStyleCastExpr
            |
          ParenExpr
            |
        BinaryOperator &
           |
           +---- CallExpr rand()

    returns:

        rand
    """

    if not isinstance(node, dict):
        return None

    if node.get("kind") == "CallExpr":

        called = find_function_name(node)

        if called in RNG_DATABASE:
            return called

    for child in node.get("inner", []):

        result = find_rng_call(child)

        if result:
            return result

    return None


# ============================================================
# FIND DESTINATION OF ASSIGNMENT
# ============================================================

def extract_assignment_destination(node):

    """
    Extract the destination of:

        iv = ...
        iv[i] = ...
    """

    if not isinstance(node, dict):
        return None

    # --------------------------------------------------------
    # Simple variable:
    #
    #     iv = ...
    # --------------------------------------------------------

    if node.get("kind") == "DeclRefExpr":

        return extract_declref_name(node)

    # --------------------------------------------------------
    # Array element:
    #
    #     iv[i] = ...
    #
    # Find the base variable 'iv'.
    # --------------------------------------------------------

    if node.get("kind") == "ArraySubscriptExpr":

        name = extract_declref_name(node)

        if name:
            return name

    # --------------------------------------------------------
    # Otherwise recursively search
    # --------------------------------------------------------

    for child in node.get("inner", []):

        result = extract_assignment_destination(child)

        if result:
            return result

    return None


# ============================================================
# EXTRACT RETURN-VALUE RNG ASSIGNMENT
# ============================================================

def extract_return_rng_assignment(
    assignment_node,
    current_function
):

    """
    Handle:

        iv[i] = rand();

    and:

        iv[i] = (uint8_t)(rand() & 0xFF);
    """

    children = assignment_node.get("inner", [])

    if len(children) < 2:
        return None

    lhs = children[0]
    rhs = children[1]

    rng_name = find_rng_call(rhs)

    if rng_name is None:
        return None

    info = RNG_DATABASE[rng_name]

    destination = extract_assignment_destination(lhs)

    return {
        "function": current_function,
        "rng": rng_name,
        "classification": info["classification"],
        "security": info["security"],
        "mode": info["mode"],
        "destination": destination,
        "size": None,
        "flags": None
    }


# ============================================================
# EXTRACT BUFFER-WRITING RNG
# ============================================================

def extract_buffer_rng(
    call_node,
    current_function,
    rng_name
):

    children = call_node.get("inner", [])

    info = RNG_DATABASE[rng_name]

    # --------------------------------------------------------
    # BCryptGenRandom
    # --------------------------------------------------------

    if rng_name == "BCryptGenRandom":

        if len(children) < 5:
            return None

        destination = extract_declref_name(
            children[2]
        )

        size = extract_integer(
            children[3]
        )

        flags = extract_integer(
            children[4]
        )

        return {
            "function": current_function,
            "rng": rng_name,
            "classification": info["classification"],
            "security": info["security"],
            "mode": info["mode"],
            "destination": destination,
            "size": size,
            "flags": flags
        }

    # --------------------------------------------------------
    # Other buffer-writing RNGs
    # --------------------------------------------------------

    if rng_name in {
        "getrandom",
        "RAND_bytes",
        "RAND_priv_bytes"
    }:

        if len(children) < 3:
            return None

        destination = extract_declref_name(
            children[1]
        )

        size = extract_integer(
            children[2]
        )

        return {
            "function": current_function,
            "rng": rng_name,
            "classification": info["classification"],
            "security": info["security"],
            "mode": info["mode"],
            "destination": destination,
            "size": size,
            "flags": None
        }

    return None


# ============================================================
# EXTRACT CRYPTO OPERATION
# ============================================================

def extract_crypto_record(
    call_node,
    current_function,
    crypto_name
):

    children = call_node.get("inner", [])

    info = CRYPTO_DATABASE[crypto_name]

    iv_index = info["iv_argument"]

    if len(children) <= iv_index:
        return None

    iv = extract_declref_name(
        children[iv_index]
    )

    return {
        "function": current_function,
        "crypto": crypto_name,
        "algorithm": info["algorithm"],
        "iv": iv
    }


# ============================================================
# AST ANALYSIS
# ============================================================

def analyze_ast(node, current_function=None):

    rng_records = []
    crypto_records = []

    if not isinstance(node, dict):
        return rng_records, crypto_records

    kind = node.get("kind", "")

    # --------------------------------------------------------
    # Track current function
    # --------------------------------------------------------

    if kind == "FunctionDecl":

        name = node.get("name")

        if name:
            current_function = name

    # --------------------------------------------------------
    # Function calls
    # --------------------------------------------------------

    if kind == "CallExpr":

        called = find_function_name(node)

        # ----------------------------------------------------
        # Buffer-writing RNG
        # ----------------------------------------------------

        if called in RNG_DATABASE:

            info = RNG_DATABASE[called]

            if info["mode"] == "BUFFER_WRITE":

                record = extract_buffer_rng(
                    node,
                    current_function,
                    called
                )

                if record:
                    rng_records.append(record)

        # ----------------------------------------------------
        # Crypto
        # ----------------------------------------------------

        if called in CRYPTO_DATABASE:

            record = extract_crypto_record(
                node,
                current_function,
                called
            )

            if record:
                crypto_records.append(record)

    # --------------------------------------------------------
    # Assignment
    # --------------------------------------------------------

    if kind == "BinaryOperator":

        if node.get("opcode") == "=":

            record = extract_return_rng_assignment(
                node,
                current_function
            )

            if record:
                rng_records.append(record)

    # --------------------------------------------------------
    # Continue traversal
    # --------------------------------------------------------

    for child in node.get("inner", []):

        child_rng, child_crypto = analyze_ast(
            child,
            current_function
        )

        rng_records.extend(child_rng)
        crypto_records.extend(child_crypto)

    return rng_records, crypto_records


# ============================================================
# DATA FLOW MATCHING
# ============================================================

def match_rng_to_crypto(
    rng_records,
    crypto_records
):

    matches = []

    for rng in rng_records:

        for crypto in crypto_records:

            if (
                rng["destination"] is not None
                and
                rng["destination"]
                ==
                crypto["iv"]
            ):

                matches.append({
                    "rng": rng,
                    "crypto": crypto
                })

    return matches


# ============================================================
# REPORT
# ============================================================

def print_report(
    rng_records,
    crypto_records,
    matches
):

    print("=" * 70)
    print("CRYPTOGRAPHIC RNG SECURITY ANALYSIS")
    print("=" * 70)

    # --------------------------------------------------------
    # RNG
    # --------------------------------------------------------

    print()
    print("Detected RNG source(s):")

    if not rng_records:

        print("    NONE")

    for rng in rng_records:

        print()
        print(
            f"    RNG              : "
            f"{rng['rng']}"
        )

        print(
            f"    Function         : "
            f"{rng['function']}"
        )

        print(
            f"    Classification   : "
            f"{rng['classification']}"
        )

        print(
            f"    Security         : "
            f"{rng['security']}"
        )

        print(
            f"    Destination      : "
            f"{rng['destination']}"
        )

        if rng["size"] is not None:

            print(
                f"    Size             : "
                f"{rng['size']} bytes"
            )

    # --------------------------------------------------------
    # CRYPTO
    # --------------------------------------------------------

    print()
    print("-" * 70)
    print("Detected cryptographic operation(s):")

    if not crypto_records:

        print("    NONE")

    for crypto in crypto_records:

        print()
        print(
            f"    Algorithm        : "
            f"{crypto['algorithm']}"
        )

        print(
            f"    Function         : "
            f"{crypto['function']}"
        )

        print(
            f"    IV               : "
            f"{crypto['iv']}"
        )

    # --------------------------------------------------------
    # DATA FLOW
    # --------------------------------------------------------

    print()
    print("-" * 70)
    print("RNG → CRYPTO DATA FLOW")

    if not matches:

        print()
        print("    NO MATCH FOUND")

    for match in matches:

        rng = match["rng"]
        crypto = match["crypto"]

        print()
        print(
            f"    {rng['rng']}"
        )

        print("         |")

        if rng["size"]:

            print(
                f"         | generates "
                f"{rng['size']} bytes"
            )

        else:

            print(
                "         | produces value"
            )

        print("         v")

        print(
            f"        {rng['destination']}"
        )

        print("         |")

        print(
            f"         | used as IV in "
            f"{crypto['function']}"
        )

        print("         v")

        print(
            f"       {crypto['algorithm']}"
        )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("FINAL RESULT")
    print("=" * 70)

    # No RNG
    if not rng_records:

        print()
        print("REVIEW")
        print(
            "Reason: No recognized RNG source "
            "was detected."
        )
        return

    # Weak RNG
    weak_rng = any(
        r["security"] == "BAD"
        for r in rng_records
    )

    if weak_rng:

        print()
        print("FLAG")
        print(
            "Reason: A non-cryptographic RNG "
            "was detected."
        )
        return

    # No crypto operation
    if not crypto_records:

        print()
        print("REVIEW")
        print(
            "Reason: No recognized cryptographic "
            "operation was detected."
        )
        return

    # No data-flow connection
    if not matches:

        print()
        print("FLAG")
        print(
            "Reason: Secure RNG detected, but "
            "its output was not shown to reach "
            "the cryptographic IV."
        )
        return

    # Everything looks good
    print()
    print("PASS")
    print(
        "Reason: A recognized cryptographic RNG "
        "feeds the AES-CBC IV."
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage:"
            " python rng_security_analyzer.py <ast.json>"
        )

        sys.exit(1)

    ast = load_json(sys.argv[1])

    rng_records, crypto_records = analyze_ast(ast)

    matches = match_rng_to_crypto(
        rng_records,
        crypto_records
    )

    print_report(
        rng_records,
        crypto_records,
        matches
    )