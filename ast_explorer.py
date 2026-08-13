import json
import sys


TARGET_FUNCTIONS = {
    "generate_iv",
    "aes_cbc_encrypt",
    "main"
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


def get_referenced_name(node):

    if not isinstance(node, dict):
        return None

    ref = node.get("referencedDecl")

    if isinstance(ref, dict):
        return ref.get("name")

    return None


def find_called_function(node):

    if not isinstance(node, dict):
        return None

    name = get_referenced_name(node)

    if name:
        return name

    for child in node.get("inner", []):

        name = find_called_function(child)

        if name:
            return name

    return None


def walk(node, current_function=None):

    if not isinstance(node, dict):
        return

    kind = node.get("kind", "")
    name = node.get("name")

    # --------------------------------------------------
    # Enter one of OUR functions
    # --------------------------------------------------

    if kind == "FunctionDecl":

        if name in TARGET_FUNCTIONS:

            current_function = name

            print()
            print("=" * 60)
            print(f"FUNCTION: {name}")
            print("=" * 60)

        else:

            # Don't let a system-header function become
            # our current function.
            if current_function not in TARGET_FUNCTIONS:
                current_function = None

    # --------------------------------------------------
    # Function call inside our function
    # --------------------------------------------------

    if kind == "CallExpr" and current_function:

        called = find_called_function(node)

        if called:

            print(
                f"FUNCTION CALL: {called}"
                f"    [inside {current_function}]"
            )

    # --------------------------------------------------
    # Continue through children
    # --------------------------------------------------

    for child in node.get("inner", []):

        walk(
            child,
            current_function
        )


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: python ast_explorer.py <ast.json>"
        )

        sys.exit(1)

    ast = load_json(sys.argv[1])

    walk(ast)