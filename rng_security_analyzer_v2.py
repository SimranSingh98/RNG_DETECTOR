import json
import sys


# ============================================================
# AST LOADER
# ============================================================

def load_ast(filename):

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
# RNG CLASSIFICATION
# ============================================================

RNG_DATABASE = {

    "BCryptGenRandom": {
        "classification": "OS cryptographic RNG",
        "security": "GOOD"
    },

    "getrandom": {
        "classification": "OS cryptographic RNG",
        "security": "GOOD"
    },

    "RAND_bytes": {
        "classification": "Cryptographic RNG",
        "security": "GOOD"
    },

    "rand": {
        "classification": "Non-cryptographic PRNG",
        "security": "BAD"
    },

    "random": {
        "classification": "Non-cryptographic PRNG",
        "security": "BAD"
    },

    "rand_r": {
        "classification": "Non-cryptographic PRNG",
        "security": "BAD"
    }
}


# ============================================================
# FIND FUNCTION REFERENCE
# ============================================================

def get_function_reference(node):

    if not isinstance(node, dict):
        return None

    if node.get("kind") == "DeclRefExpr":

        ref = node.get("referencedDecl")

        if isinstance(ref, dict):

            if ref.get("kind") == "FunctionDecl":
                return ref

    for child in node.get("inner", []):

        result = get_function_reference(child)

        if result:
            return result

    return None


# ============================================================
# FIND VARIABLE REFERENCE
# ============================================================

def get_variable_reference(node):

    if not isinstance(node, dict):
        return None

    if node.get("kind") == "DeclRefExpr":

        ref = node.get("referencedDecl")

        if isinstance(ref, dict):

            if ref.get("kind") in {
                "VarDecl",
                "ParmVarDecl"
            }:

                return ref

    for child in node.get("inner", []):

        result = get_variable_reference(child)

        if result:
            return result

    return None


# ============================================================
# COLLECT FUNCTION DECLARATIONS
# ============================================================

def collect_functions(
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

        collect_functions(
            child,
            functions
        )

    return functions


# ============================================================
# FIND CALLED FUNCTION
# ============================================================

def get_called_function(node):

    if not isinstance(node, dict):
        return None

    children = node.get("inner", [])

    if not children:
        return None

    return get_function_reference(
        children[0]
    )


# ============================================================
# COLLECT FUNCTION PARAMETER MAPPINGS
# ============================================================

def collect_parameter_mappings(
    node,
    functions,
    mappings=None,
    current_function=None
):

    if mappings is None:
        mappings = []

    if not isinstance(node, dict):
        return mappings

    # Track current function
    if node.get("kind") == "FunctionDecl":

        name = node.get("name")

        if name:
            current_function = name

    # Process call
    if node.get("kind") == "CallExpr":

        function_ref = get_called_function(node)

        if function_ref:

            called_name = function_ref.get("name")

            if called_name in functions:

                parameters = functions[
                    called_name
                ]["parameters"]

                children = node.get("inner", [])

                arguments = children[1:]

                for index, argument in enumerate(
                    arguments
                ):

                    if index >= len(parameters):
                        break

                    # Do not recursively treat sizeof()
                    # as a variable argument.
                    if (
                        argument.get("kind")
                        == "UnaryExprOrTypeTraitExpr"
                    ):
                        continue

                    variable = get_variable_reference(
                        argument
                    )

                    if variable is None:
                        continue

                    parameter = parameters[index]

                    mappings.append({

                        "caller_function":
                            current_function,

                        "caller_name":
                            variable.get("name"),

                        "caller_id":
                            variable.get("id"),

                        "called_function":
                            called_name,

                        "parameter_name":
                            parameter.get("name"),

                        "parameter_id":
                            parameter.get("id"),

                        "argument_index":
                            index
                    })

    for child in node.get("inner", []):

        collect_parameter_mappings(
            child,
            functions,
            mappings,
            current_function
        )

    return mappings


# ============================================================
# FIND RNG CALL INSIDE AN EXPRESSION
# ============================================================

def find_rng_call(node):

    if not isinstance(node, dict):
        return None

    if node.get("kind") == "CallExpr":

        function_ref = get_called_function(node)

        if function_ref:

            name = function_ref.get("name")

            if name in RNG_DATABASE:

                return name

    for child in node.get("inner", []):

        result = find_rng_call(child)

        if result:
            return result

    return None


# ============================================================
# FIND ARRAY BASE
# ============================================================

def get_array_base(node):

    if not isinstance(node, dict):
        return None

    if node.get("kind") == "ArraySubscriptExpr":

        children = node.get("inner", [])

        if children:

            return get_variable_reference(
                children[0]
            )

    return None


# ============================================================
# FIND RNG → MEMORY WRITES
# ============================================================

def collect_rng_writes(
    node,
    current_function=None,
    writes=None
):

    if writes is None:
        writes = []

    if not isinstance(node, dict):
        return writes

    if node.get("kind") == "FunctionDecl":

        name = node.get("name")

        if name:
            current_function = name

    # Assignment
    if node.get("kind") == "BinaryOperator":

        if node.get("opcode") == "=":

            children = node.get("inner", [])

            if len(children) >= 2:

                lhs = children[0]
                rhs = children[1]

                rng = find_rng_call(rhs)

                if rng:

                    # Array assignment:
                    #
                    # iv[i] = rand();

                    if (
                        lhs.get("kind")
                        == "ArraySubscriptExpr"
                    ):

                        destination = get_array_base(
                            lhs
                        )

                        if destination:

                            writes.append({

                                "function":
                                    current_function,

                                "rng":
                                    rng,

                                "destination":
                                    destination
                            })

                    else:

                        destination = (
                            get_variable_reference(
                                lhs
                            )
                        )

                        if destination:

                            writes.append({

                                "function":
                                    current_function,

                                "rng":
                                    rng,

                                "destination":
                                    destination
                            })

    for child in node.get("inner", []):

        collect_rng_writes(
            child,
            current_function,
            writes
        )

    return writes


# ============================================================
# FIND DIRECT RNG DESTINATION
# ============================================================

def collect_direct_rng_calls(
    node,
    current_function=None,
    results=None
):

    if results is None:
        results = []

    if not isinstance(node, dict):
        return results

    if node.get("kind") == "FunctionDecl":

        name = node.get("name")

        if name:
            current_function = name

    if node.get("kind") == "CallExpr":

        function_ref = get_called_function(node)

        if function_ref:

            name = function_ref.get("name")

            if name in RNG_DATABASE:

                children = node.get("inner", [])

                arguments = children[1:]

                destination = None

                # BCryptGenRandom:
                #
                # argument 1 = buffer
                #
                # RAND_bytes:
                #
                # argument 0 = buffer

                if name == "BCryptGenRandom":

                    if len(arguments) >= 2:

                        destination = (
                            get_variable_reference(
                                arguments[1]
                            )
                        )

                elif name == "RAND_bytes":

                    if len(arguments) >= 1:

                        destination = (
                            get_variable_reference(
                                arguments[0]
                            )
                        )

                elif name == "getrandom":

                    if len(arguments) >= 1:

                        destination = (
                            get_variable_reference(
                                arguments[0]
                            )
                        )

                if destination:

                    results.append({

                        "function":
                            current_function,

                        "rng":
                            name,

                        "destination":
                            destination
                    })

    for child in node.get("inner", []):

        collect_direct_rng_calls(
            child,
            current_function,
            results
        )

    return results


# ============================================================
# FIND CRYPTO CALLS
# ============================================================

def collect_crypto_calls(
    node,
    current_function=None,
    results=None
):

    if results is None:
        results = []

    if not isinstance(node, dict):
        return results

    if node.get("kind") == "FunctionDecl":

        name = node.get("name")

        if name:
            current_function = name

    if node.get("kind") == "CallExpr":

        function_ref = get_called_function(node)

        if function_ref:

            name = function_ref.get("name")

            if name in {
                "aes_cbc_encrypt",
                "AES_CBC_encrypt"
            }:

                children = node.get("inner", [])

                arguments = children[1:]

                iv = None

                if len(arguments) >= 2:

                    iv = get_variable_reference(
                        arguments[1]
                    )

                results.append({

                    "function":
                        current_function,

                    "algorithm":
                        "AES-CBC",

                    "iv":
                        iv
                })

    for child in node.get("inner", []):

        collect_crypto_calls(
            child,
            current_function,
            results
        )

    return results


# ============================================================
# FIND PARAMETER ALIAS
# ============================================================

def find_alias(
    mappings,
    function_name,
    parameter_name
):

    for mapping in mappings:

        if (
            mapping["called_function"]
            == function_name
            and
            mapping["parameter_name"]
            == parameter_name
        ):

            return mapping

    return None


# ============================================================
# PRINT RESULT
# ============================================================

def analyze(ast):

    functions = collect_functions(ast)

    mappings = collect_parameter_mappings(
        ast,
        functions
    )

    rng_writes = collect_rng_writes(ast)

    direct_rng = collect_direct_rng_calls(ast)

    crypto = collect_crypto_calls(ast)

    print()
    print("=" * 70)
    print("CRYPTOGRAPHIC RNG SECURITY ANALYSIS")
    print("=" * 70)

    # --------------------------------------------------------
    # RNG
    # --------------------------------------------------------

    print()
    print("DETECTED RNG SOURCE(S)")
    print("-" * 70)

    all_rng = []

    all_rng.extend(rng_writes)
    all_rng.extend(direct_rng)

    if not all_rng:

        print("No recognized RNG detected.")

    for item in all_rng:

        rng = item["rng"]

        info = RNG_DATABASE[rng]

        destination = item.get(
            "destination"
        )

        print()
        print(
            f"RNG              : {rng}"
        )

        print(
            f"Function         : "
            f"{item['function']}"
        )

        print(
            f"Classification   : "
            f"{info['classification']}"
        )

        print(
            f"Security         : "
            f"{info['security']}"
        )

        if destination:

            print(
                f"Destination      : "
                f"{destination.get('name')}"
            )

    # --------------------------------------------------------
    # CRYPTO
    # --------------------------------------------------------

    print()
    print("-" * 70)
    print("DETECTED CRYPTOGRAPHIC OPERATION(S)")
    print("-" * 70)

    for operation in crypto:

        iv = operation["iv"]

        print()
        print(
            f"Algorithm        : "
            f"{operation['algorithm']}"
        )

        print(
            f"Function         : "
            f"{operation['function']}"
        )

        if iv:

            print(
                f"IV               : "
                f"{iv.get('name')}"
            )

    # --------------------------------------------------------
    # DATA FLOW
    # --------------------------------------------------------

    print()
    print("-" * 70)
    print("RNG → CRYPTO DATA FLOW")
    print("-" * 70)

    security_relevant_bad_rng = False
    security_relevant_good_rng = False

    for operation in crypto:

        iv = operation["iv"]

        if iv is None:
            continue

        iv_name = iv.get("name")
        iv_id = iv.get("id")

        for item in all_rng:

            destination = item.get(
                "destination"
            )

            if destination is None:
                continue

            destination_name = (
                destination.get("name")
            )

            destination_id = (
                destination.get("id")
            )

            # ------------------------------------------------
            # Direct match
            # ------------------------------------------------

            match = (
                destination_name == iv_name
                or
                destination_id == iv_id
            )

            # ------------------------------------------------
            # Interprocedural match
            # ------------------------------------------------

            if not match:

                alias = find_alias(
                    mappings,
                    item["function"],
                    destination_name
                )

                if alias:

                    caller_name = (
                        alias["caller_name"]
                    )

                    caller_id = (
                        alias["caller_id"]
                    )

                    match = (
                        caller_name == iv_name
                        or
                        caller_id == iv_id
                    )

            if match:

                rng = item["rng"]

                info = RNG_DATABASE[rng]

                print()
                print(
                    f"{rng}()"
                )

                print(
                    "    |"
                )

                print(
                    "    | RNG data"
                )

                print(
                    "    v"
                )

                print(
                    f"{destination_name}"
                )

                print(
                    "    |"
                )

                print(
                    "    | cryptographic IV"
                )

                print(
                    "    v"
                )

                print(
                    "AES-CBC"
                )

                if info["security"] == "BAD":

                    security_relevant_bad_rng = True

                else:

                    security_relevant_good_rng = True

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("FINAL RESULT")
    print("=" * 70)

    if security_relevant_bad_rng:

        print()
        print("FLAG")

        print()
        print(
            "Reason: A non-cryptographic RNG "
            "feeds an AES-CBC IV."
        )

    elif security_relevant_good_rng:

        print()
        print("PASS")

        print()
        print(
            "Reason: A recognized cryptographic "
            "RNG feeds an AES-CBC IV."
        )

    else:

        print()
        print("REVIEW")

        print()
        print(
            "Reason: No complete RNG → "
            "cryptographic data flow was established."
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage:"
            " python rng_security_analyzer_v2.py <ast.json>"
        )

        sys.exit(1)

    ast = load_ast(sys.argv[1])

    analyze(ast)