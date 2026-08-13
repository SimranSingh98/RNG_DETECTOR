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


def get_referenced_name(node):

    if not isinstance(node, dict):
        return None

    ref = node.get("referencedDecl")

    if isinstance(ref, dict):
        return ref.get("name")

    return None


def contains_rand(node):

    if not isinstance(node, dict):
        return False

    if node.get("kind") == "CallExpr":

        # Look for rand in this call.
        stack = [node]

        while stack:

            current = stack.pop()

            name = get_referenced_name(current)

            if name == "rand":
                return True

            stack.extend(
                current.get("inner", [])
            )

    for child in node.get("inner", []):

        if contains_rand(child):
            return True

    return False


def print_tree(node, depth=0):

    if not isinstance(node, dict):
        return

    kind = node.get("kind", "")

    name = ""

    if kind == "DeclRefExpr":

        ref = node.get("referencedDecl")

        if isinstance(ref, dict):
            name = (
                f" -> "
                f"{ref.get('kind')}: "
                f"{ref.get('name')}"
            )

    elif kind == "IntegerLiteral":

        name = (
            f" -> {node.get('value')}"
        )

    print(
        "  " * depth
        + kind
        + name
    )

    for child in node.get("inner", []):

        print_tree(
            child,
            depth + 1
        )


def walk(node):

    if not isinstance(node, dict):
        return

    if node.get("kind") == "BinaryOperator":

        # '=' assignment
        if node.get("opcode") == "=":

            if contains_rand(node):

                print()
                print("=" * 70)
                print("ASSIGNMENT CONTAINING rand()")
                print("=" * 70)

                print_tree(node)

                print()

    for child in node.get("inner", []):

        walk(child)


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python ast_assignment_debug.py <ast.json>"
        )

        sys.exit(1)

    ast = load_json(sys.argv[1])

    walk(ast)