import json
import sys


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


def walk_function(node):

    if not isinstance(node, dict):
        return

    if node.get("kind") != "FunctionDecl":
        return

    function_name = node.get("name")

    if function_name not in {
        "generate_iv",
        "aes_cbc_encrypt",
        "main"
    }:
        return

    print()
    print("=" * 70)
    print(f"FUNCTION: {function_name}")
    print("=" * 70)

    for child in node.get("inner", []):

        if child.get("kind") == "ParmVarDecl":

            print(
                f"PARAMETER: "
                f"{child.get('name')}"
            )

            print(
                f"    ID: {child.get('id')}"
            )

        elif child.get("kind") == "CompoundStmt":

            find_local_variables(child)


def find_local_variables(node):

    if not isinstance(node, dict):
        return

    if node.get("kind") == "VarDecl":

        print(
            f"LOCAL VARIABLE: "
            f"{node.get('name')}"
        )

        print(
            f"    ID: {node.get('id')}"
        )

    for child in node.get("inner", []):

        find_local_variables(child)


def walk(node):

    if not isinstance(node, dict):
        return

    walk_function(node)

    for child in node.get("inner", []):

        walk(child)


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python ast_function_vars.py <ast.json>"
        )

        sys.exit(1)

    ast = load_json(sys.argv[1])

    walk(ast)