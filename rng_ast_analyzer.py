import json
import sys


# ============================================================
# RNG CLASSIFICATION
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
# LOAD CLANG AST JSON
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

    """
    Recursively find the first referenced declaration.
    """

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

    """
    Find the function referenced by a CallExpr.
    """

    for child in call_node.get("inner", []):

        ref = find_referenced_decl(child)

        if ref and ref.get("kind") == "FunctionDecl":

            return ref.get("name")

    return None


def extract_declref_name(node):

    """
    Return the name referenced by a DeclRefExpr.
    """

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

    """
    Find an IntegerLiteral recursively.
    """

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
# EXTRACT BCryptGenRandom()
# ============================================================

def extract_bcrypt_rng(call_node, current_function):

    children = call_node.get("inner", [])

    # --------------------------------------------------------
    # Child 0 = function reference
    # Child 1 = hAlgorithm
    # Child 2 = pbBuffer
    # Child 3 = cbBuffer
    # Child 4 = dwFlags
    # --------------------------------------------------------

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
        "rng": "BCryptGenRandom",
        "classification": RNG_DATABASE[
            "BCryptGenRandom"
        ]["classification"],
        "security": RNG_DATABASE[
            "BCryptGenRandom"
        ]["security"],
        "mode": RNG_DATABASE[
            "BCryptGenRandom"
        ]["mode"],
        "destination": destination,
        "size": size,
        "flags": flags
    }


# ============================================================
# WALK AST
# ============================================================

def analyze_ast(node, current_function=None):

    records = []

    if not isinstance(node, dict):
        return records

    kind = node.get("kind", "")

    # --------------------------------------------------------
    # Track function
    # --------------------------------------------------------

    if kind == "FunctionDecl":

        name = node.get("name")

        if name:
            current_function = name

    # --------------------------------------------------------
    # Detect CallExpr
    # --------------------------------------------------------

    if kind == "CallExpr":

        called = find_function_name(node)

        if called in RNG_DATABASE:

            if called == "BCryptGenRandom":

                record = extract_bcrypt_rng(
                    node,
                    current_function
                )

                if record:
                    records.append(record)

    # --------------------------------------------------------
    # Continue recursively
    # --------------------------------------------------------

    for child in node.get("inner", []):

        records.extend(
            analyze_ast(
                child,
                current_function
            )
        )

    return records


# ============================================================
# PRINT RESULT
# ============================================================

def print_report(records):

    print("=" * 70)
    print("SEMANTIC RNG SOURCE ANALYSIS")
    print("=" * 70)

    if not records:

        print()
        print("No recognized RNG calls found.")
        print()
        return

    for record in records:

        print()
        print("RNG RECORD")
        print("-" * 70)

        print(
            f"Function       : "
            f"{record['function']}"
        )

        print(
            f"RNG source     : "
            f"{record['rng']}"
        )

        print(
            f"Classification : "
            f"{record['classification']}"
        )

        print(
            f"Destination    : "
            f"{record['destination']}"
        )

        print(
            f"Size           : "
            f"{record['size']} bytes"
        )

        print(
            f"Flags          : "
            f"{record['flags']}"
        )

        print()
        print("Semantic flow:")
        print()
        print(
            f"    {record['rng']}()"
        )
        print("         |")
        print(
            f"         | writes "
            f"{record['size']} bytes"
        )
        print("         v")
        print(
            f"       {record['destination']}"
        )

        print()

        print(
            f"Security status: "
            f"{record['security']}"
        )

    print()
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python rng_ast_analyzer.py <ast.json>"
        )

        sys.exit(1)

    ast_file = sys.argv[1]

    ast = load_json(ast_file)

    records = analyze_ast(ast)

    print_report(records)