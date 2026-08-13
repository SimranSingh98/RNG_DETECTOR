import json
import sys


TARGET_RNGS = {
    "BCryptGenRandom",
    "rand",
    "random",
    "getrandom",
    "RAND_bytes",
    "RAND_priv_bytes"
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


def find_function_reference(node):

    if not isinstance(node, dict):
        return None

    name = get_referenced_name(node)

    if name:
        return name

    for child in node.get("inner", []):

        name = find_function_reference(child)

        if name:
            return name

    return None


def describe_node(node, indent=0):

    if not isinstance(node, dict):
        return

    kind = node.get("kind", "")

    # ---------------------------------------------
    # Direct variable/function reference
    # ---------------------------------------------

    if kind == "DeclRefExpr":

        ref = node.get("referencedDecl", {})

        if isinstance(ref, dict):

            ref_kind = ref.get("kind", "")
            ref_name = ref.get("name", "")

            print(
                " " * indent
                + f"DeclRefExpr -> "
                f"{ref_kind}: {ref_name}"
            )

            return

    # ---------------------------------------------
    # Integer
    # ---------------------------------------------

    if kind == "IntegerLiteral":

        print(
            " " * indent
            + f"IntegerLiteral -> "
            f"{node.get('value')}"
        )

        return

    # ---------------------------------------------
    # Null pointer / constants / other expressions
    # ---------------------------------------------

    if kind in {
        "GNUNullExpr",
        "CXXNullPtrLiteralExpr",
        "CharacterLiteral",
        "FloatingLiteral",
        "StringLiteral"
    }:

        print(
            " " * indent
            + kind
        )

        return

    # ---------------------------------------------
    # General node
    # ---------------------------------------------

    print(
        " " * indent
        + kind
    )

    for child in node.get("inner", []):

        describe_node(
            child,
            indent + 2
        )


def walk(node, current_function=None):

    if not isinstance(node, dict):
        return

    kind = node.get("kind", "")

    # ---------------------------------------------
    # Track function
    # ---------------------------------------------

    if kind == "FunctionDecl":

        name = node.get("name")

        if name:
            current_function = name

    # ---------------------------------------------
    # Find CallExpr
    # ---------------------------------------------

    if kind == "CallExpr":

        called = find_function_reference(node)

        if called in TARGET_RNGS:

            print()
            print("=" * 70)
            print(f"RNG CALL: {called}")
            print(f"Inside function: {current_function}")
            print("=" * 70)

            children = node.get("inner", [])

            print(
                f"Total AST children: {len(children)}"
            )

            print()

            for index, child in enumerate(children):

                print(
                    f"ARGUMENT / CHILD {index}"
                )

                describe_node(
                    child,
                    indent=2
                )

                print()

    # ---------------------------------------------
    # Continue traversal
    # ---------------------------------------------

    for child in node.get("inner", []):

        walk(
            child,
            current_function
        )


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python ast_rng_arguments.py <ast.json>"
        )

        sys.exit(1)

    ast = load_json(sys.argv[1])

    walk(ast)