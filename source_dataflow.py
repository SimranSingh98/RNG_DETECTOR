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
# FIND FUNCTION DECLARATION REFERENCE
# ============================================================

def get_called_function(node):

    if not isinstance(node, dict):
        return None

    # A CallExpr's first child normally refers to the function.
    children = node.get("inner", [])

    if not children:
        return None

    first = children[0]

    # Search inside implicit casts, etc.
    stack = [first]

    while stack:

        current = stack.pop()

        if not isinstance(current, dict):
            continue

        if current.get("kind") == "DeclRefExpr":

            ref = current.get("referencedDecl")

            if isinstance(ref, dict):

                if ref.get("kind") == "FunctionDecl":

                    return ref

        stack.extend(
            current.get("inner", [])
        )

    return None


# ============================================================
# GET VARIABLE DECLARATION REFERENCE
# ============================================================

def get_variable_reference(node):

    if not isinstance(node, dict):
        return None

    # Search recursively, but only for variable references.
    stack = [node]

    while stack:

        current = stack.pop()

        if not isinstance(current, dict):
            continue

        if current.get("kind") == "DeclRefExpr":

            ref = current.get("referencedDecl")

            if isinstance(ref, dict):

                if ref.get("kind") in {
                    "VarDecl",
                    "ParmVarDecl"
                }:

                    return ref

        stack.extend(
            current.get("inner", [])
        )

    return None


# ============================================================
# COLLECT COMPLETE FUNCTION DECLARATIONS
# ============================================================

def collect_function_declarations(
    node,
    functions=None
):

    if functions is None:
        functions = {}

    if not isinstance(node, dict):
        return functions

    if node.get("kind") == "FunctionDecl":

        name = node.get("name")

        if name:

            parameters = []

            for child in node.get("inner", []):

                if child.get("kind") == "ParmVarDecl":

                    parameters.append({
                        "name": child.get("name"),
                        "id": child.get("id")
                    })

            functions[name] = {
                "name": name,
                "parameters": parameters
            }

    for child in node.get("inner", []):

        collect_function_declarations(
            child,
            functions
        )

    return functions


# ============================================================
# COLLECT CALL MAPPINGS
# ============================================================

def collect_call_mappings(
    node,
    functions,
    mappings=None,
    current_function=None
):

    if mappings is None:
        mappings = []

    if not isinstance(node, dict):
        return mappings

    # --------------------------------------------------------
    # Enter a function
    # --------------------------------------------------------

    if node.get("kind") == "FunctionDecl":

        name = node.get("name")

        if name:
            current_function = name

    # --------------------------------------------------------
    # Call expression
    # --------------------------------------------------------

    if node.get("kind") == "CallExpr":

        function_ref = get_called_function(node)

        if function_ref:

            called_function = function_ref.get("name")

            # Only analyze functions that we have complete
            # declarations for.
            if called_function in functions:

                parameters = functions[
                    called_function
                ]["parameters"]

                children = node.get("inner", [])

                # Child 0 = function reference.
                arguments = children[1:]

                for index, argument in enumerate(
                    arguments
                ):

                    if index >= len(parameters):
                        break

                    variable_ref = (
                        get_variable_reference(
                            argument
                        )
                    )

                    if variable_ref is None:
                        continue

                    parameter = parameters[index]

                    mappings.append({

                        "caller_function":
                            current_function,

                        "caller_variable":
                            variable_ref.get("name"),

                        "caller_id":
                            variable_ref.get("id"),

                        "called_function":
                            called_function,

                        "parameter":
                            parameter.get("name"),

                        "parameter_id":
                            parameter.get("id"),

                        "argument_index":
                            index
                    })

    # --------------------------------------------------------
    # Continue AST traversal
    # --------------------------------------------------------

    for child in node.get("inner", []):

        collect_call_mappings(
            child,
            functions,
            mappings,
            current_function
        )

    return mappings


# ============================================================
# PRINT RESULTS
# ============================================================

def print_results(
    functions,
    mappings
):

    print()
    print("=" * 70)
    print("SOURCE-LEVEL DATA-FLOW GRAPH")
    print("=" * 70)

    print()
    print("FUNCTION PARAMETER MAPPINGS")
    print("-" * 70)

    if not mappings:

        print("No mappings found.")

        return

    for mapping in mappings:

        print(
            f"{mapping['caller_function']}::"
            f"{mapping['caller_variable']}"
        )

        print("    |")

        print(
            f"    | argument "
            f"{mapping['argument_index']}"
        )

        print("    v")

        print(
            f"{mapping['called_function']}::"
            f"{mapping['parameter']}"
        )

        print(
            f"    caller ID    : "
            f"{mapping['caller_id']}"
        )

        print(
            f"    parameter ID : "
            f"{mapping['parameter_id']}"
        )

        print()

    # --------------------------------------------------------
    # IV aliases
    # --------------------------------------------------------

    print("-" * 70)
    print("IV ALIASES")
    print("-" * 70)

    iv_mappings = []

    for mapping in mappings:

        if (
            mapping["caller_variable"] == "iv"
            and
            mapping["parameter"] == "iv"
        ):

            iv_mappings.append(mapping)

    if not iv_mappings:

        print("No IV aliases found.")

        return

    for mapping in iv_mappings:

        print(
            f"{mapping['caller_function']}::iv"
            f"  <-->  "
            f"{mapping['called_function']}::iv"
        )

        print(
            f"    caller ID    : "
            f"{mapping['caller_id']}"
        )

        print(
            f"    parameter ID : "
            f"{mapping['parameter_id']}"
        )

        print()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage:"
            " python source_dataflow.py <ast.json>"
        )

        sys.exit(1)

    ast = load_json(sys.argv[1])

    functions = collect_function_declarations(
        ast
    )

    mappings = collect_call_mappings(
        ast,
        functions
    )

    print_results(
        functions,
        mappings
    )