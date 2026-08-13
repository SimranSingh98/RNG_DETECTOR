import json
import sys


# ============================================================
# LOAD AST
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
# FIND RNG CALL
# ============================================================

def find_rng_call(node):

    if not isinstance(node, dict):
        return None

    if node.get("kind") == "CallExpr":

        children = node.get("inner", [])

        for child in children:

            if not isinstance(child, dict):
                continue

            if child.get("kind") == "ImplicitCastExpr":

                for nested in child.get("inner", []):

                    if (
                        nested.get("kind")
                        == "DeclRefExpr"
                    ):

                        ref = nested.get(
                            "referencedDecl"
                        )

                        if (
                            isinstance(ref, dict)
                            and
                            ref.get("kind")
                            == "FunctionDecl"
                        ):

                            name = ref.get("name")

                            if name in {
                                "rand",
                                "random",
                                "rand_r"
                            }:
                                return name

    # Recursive search
    for child in node.get("inner", []):

        result = find_rng_call(child)

        if result:
            return result

    return None


# ============================================================
# FIND ARRAY BASE VARIABLE
# ============================================================

def find_array_base(node):

    if not isinstance(node, dict):
        return None

    if node.get("kind") == "ArraySubscriptExpr":

        children = node.get("inner", [])

        if not children:
            return None

        base = children[0]

        return find_variable(base)

    for child in node.get("inner", []):

        result = find_array_base(child)

        if result:
            return result

    return None


# ============================================================
# FIND VARIABLE REFERENCE
# ============================================================

def find_variable(node):

    if not isinstance(node, dict):
        return None

    if node.get("kind") == "DeclRefExpr":

        ref = node.get("referencedDecl")

        if isinstance(ref, dict):

            if ref.get("kind") in {
                "VarDecl",
                "ParmVarDecl"
            }:

                return {
                    "name": ref.get("name"),
                    "id": ref.get("id"),
                    "kind": ref.get("kind")
                }

    for child in node.get("inner", []):

        result = find_variable(child)

        if result:
            return result

    return None


# ============================================================
# FIND INDEX VARIABLE
# ============================================================

def find_array_index(node):

    if not isinstance(node, dict):
        return None

    if node.get("kind") == "ArraySubscriptExpr":

        children = node.get("inner", [])

        if len(children) >= 2:

            return find_variable(
                children[1]
            )

    for child in node.get("inner", []):

        result = find_array_index(child)

        if result:
            return result

    return None


# ============================================================
# FIND ASSIGNMENTS INVOLVING RNG
# ============================================================

def find_rng_assignments(
    node,
    current_function=None,
    results=None
):

    if results is None:
        results = []

    if not isinstance(node, dict):
        return results

    # Track function
    if node.get("kind") == "FunctionDecl":

        name = node.get("name")

        if name:
            current_function = name

    # --------------------------------------------------------
    # Assignment
    # --------------------------------------------------------

    if node.get("kind") == "BinaryOperator":

        opcode = node.get("opcode")

        if opcode == "=":

            children = node.get("inner", [])

            if len(children) >= 2:

                lhs = children[0]
                rhs = children[1]

                rng = find_rng_call(rhs)

                if rng:

                    # Is LHS an array element?
                    if (
                        lhs.get("kind")
                        == "ArraySubscriptExpr"
                    ):

                        destination = (
                            find_array_base(lhs)
                        )

                        index = (
                            find_array_index(lhs)
                        )

                        if destination:

                            results.append({

                                "function":
                                    current_function,

                                "rng":
                                    rng,

                                "destination":
                                    destination,

                                "index":
                                    index
                            })

                    else:

                        destination = (
                            find_variable(lhs)
                        )

                        if destination:

                            results.append({

                                "function":
                                    current_function,

                                "rng":
                                    rng,

                                "destination":
                                    destination,

                                "index":
                                    None
                            })

    # Continue traversal
    for child in node.get("inner", []):

        find_rng_assignments(
            child,
            current_function,
            results
        )

    return results


# ============================================================
# PRINT RESULTS
# ============================================================

def print_results(results):

    print()
    print("=" * 70)
    print("RNG → MEMORY WRITE ANALYSIS")
    print("=" * 70)

    if not results:

        print()
        print("No RNG-to-memory assignments detected.")
        return

    for result in results:

        print()
        print("RNG SOURCE")
        print("-" * 70)

        print(
            f"Function     : "
            f"{result['function']}"
        )

        print(
            f"RNG          : "
            f"{result['rng']}"
        )

        print()

        print("DESTINATION")
        print("-" * 70)

        destination = result["destination"]

        print(
            f"Variable     : "
            f"{destination['name']}"
        )

        print(
            f"Declaration  : "
            f"{destination['kind']}"
        )

        print(
            f"Declaration ID: "
            f"{destination['id']}"
        )

        if result["index"]:

            print()

            print(
                f"Array index  : "
                f"{result['index']['name']}"
            )

        print()

        print("SEMANTIC FLOW")
        print("-" * 70)

        print(
            f"{result['rng']}()"
        )

        print("    |")

        print("    | generated value")

        print("    v")

        if result["index"]:

            print(
                f"{destination['name']}"
                f"[{result['index']['name']}]"
            )

        else:

            print(
                destination["name"]
            )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage:"
            " python array_rng_detector.py <ast.json>"
        )

        sys.exit(1)

    ast = load_json(sys.argv[1])

    results = find_rng_assignments(ast)

    print_results(results)