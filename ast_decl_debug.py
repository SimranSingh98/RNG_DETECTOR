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


def print_declref(node):

    if not isinstance(node, dict):
        return

    if node.get("kind") == "DeclRefExpr":

        ref = node.get("referencedDecl")

        if isinstance(ref, dict):

            if ref.get("name") == "iv":

                print(
                    "DeclRefExpr:"
                )

                print(
                    f"    name : {ref.get('name')}"
                )

                print(
                    f"    kind : {ref.get('kind')}"
                )

                print(
                    f"    id   : {ref.get('id')}"
                )

                print()
    for child in node.get("inner", []):

        print_declref(child)


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python ast_decl_debug.py <ast.json>"
        )

        sys.exit(1)

    ast = load_json(sys.argv[1])

    print_declref(ast)