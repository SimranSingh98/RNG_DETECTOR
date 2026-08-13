import json
import sys


TARGET_CRYPTO_FUNCTIONS = {
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


def get_referenced_decl(node):

    if not isinstance(node, dict):
        return None

    ref = node.get("referencedDecl")

    if isinstance(ref, dict):
        return ref

    return None


def find_function_name(node):

    if not isinstance(node, dict):
        return None

    ref = get_referenced_decl(node)

    if ref and ref.get("kind") == "FunctionDecl":
        return ref.get("name")

    for child in node.get("inner", []):

        name = find_function_name(child)

        if name:
            return name

    return None


def describe_argument(node, indent=2):

    if not isinstance(node, dict):
        return

    kind = node.get("kind", "")

    # --------------------------------------------------------
    # Variable/function reference
    # --------------------------------------------------------

    if kind == "DeclRefExpr":

        ref = node.get("referencedDecl")

        if isinstance(ref, dict):

            print(
                " " * indent
                + f"DeclRefExpr -> "
                f"{ref.get('kind')}: "
                f"{ref.get('name')}"
            )

            return

    # --------------------------------------------------------
    # Integer
    # --------------------------------------------------------

    if kind == "IntegerLiteral":

        print(
            " " * indent
            + f"IntegerLiteral -> "
            f"{node.get('value')}"
        )

        return

    # --------------------------------------------------------
    # Other expression
    # --------------------------------------------------------

    print(
        " " * indent
        + kind
    )

    for child in node.get("inner", []):

        describe_argument(
            child,
            indent + 2
        )


def walk(node, current_function=None):

    if not isinstance(node, dict):
        return

    kind = node.get("kind", "")

    if kind == "FunctionDecl":

        name = node.get("name")

        if name:
            current_function = name

    if kind == "CallExpr":

        called = find_function_name(node)

        if called in TARGET_CRYPTO_FUNCTIONS:

            print()
            print("=" * 70)
            print(
                f"CRYPTO CALL: {called}"
            )
            print(
                f"Inside function: "
                f"{current_function}"
            )
            print("=" * 70)

            children = node.get("inner", [])

            print(
                f"Total AST children: "
                f"{len(children)}"
            )

            print()

            for index, child in enumerate(children):

                print(
                    f"ARGUMENT / CHILD {index}"
                )

                describe_argument(
                    child
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
            "python ast_crypto_arguments.py "
            "<ast.json>"
        )

        sys.exit(1)

    ast = load_json(sys.argv[1])

    walk(ast)