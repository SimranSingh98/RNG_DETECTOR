import json
import sys


TARGET_FUNCTIONS = {
    "generate_iv",
    "aes_cbc_encrypt"
}


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


def get_function_reference(node):

    if not isinstance(node, dict):
        return None

    ref = node.get("referencedDecl")

    if isinstance(ref, dict):

        if ref.get("kind") == "FunctionDecl":
            return ref

    for child in node.get("inner", []):

        ref = get_function_reference(child)

        if ref:
            return ref

    return None


def get_decl_reference(node):

    if not isinstance(node, dict):
        return None

    ref = node.get("referencedDecl")

    if isinstance(ref, dict):

        if ref.get("kind") in {
            "VarDecl",
            "ParmVarDecl"
        }:
            return ref

    for child in node.get("inner", []):

        ref = get_decl_reference(child)

        if ref:
            return ref

    return None


def walk(node, current_function=None):

    if not isinstance(node, dict):
        return

    kind = node.get("kind")

    # --------------------------------------------------------
    # Track current function
    # --------------------------------------------------------

    if kind == "FunctionDecl":

        name = node.get("name")

        if name:
            current_function = name

    # --------------------------------------------------------
    # Analyze calls
    # --------------------------------------------------------

    if kind == "CallExpr":

        function_ref = get_function_reference(node)

        if function_ref:

            called_function = function_ref.get("name")

            if called_function in TARGET_FUNCTIONS:

                children = node.get("inner", [])

                print()
                print("=" * 70)
                print(
                    f"CALL: {called_function}"
                )
                print(
                    f"CALLER: {current_function}"
                )
                print("=" * 70)

                # Child 0 is the function.
                arguments = children[1:]

                for index, argument in enumerate(arguments):

                    ref = get_decl_reference(argument)

                    if ref:

                        print(
                            f"Argument {index}:"
                        )

                        print(
                            f"    Caller variable : "
                            f"{ref.get('name')}"
                        )

                        print(
                            f"    Caller ID       : "
                            f"{ref.get('id')}"
                        )

                    else:

                        print(
                            f"Argument {index}: "
                            f"complex expression"
                        )

                print()

    for child in node.get("inner", []):

        walk(
            child,
            current_function
        )


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python ast_parameter_mapping.py <ast.json>"
        )

        sys.exit(1)

    ast = load_json(sys.argv[1])

    walk(ast)