class SecurityFlow:

    def __init__(self):

        self.edges = []

    def add_edge(
        self,
        source,
        destination,
        relationship
    ):

        self.edges.append({
            "source": source,
            "destination": destination,
            "relationship": relationship
        })

    def print_graph(self):

        print()
        print("=" * 70)
        print("SEMANTIC SECURITY DATA FLOW")
        print("=" * 70)

        for edge in self.edges:

            print(
                f"{edge['source']}"
            )

            print("    |")

            print(
                f"    | {edge['relationship']}"
            )

            print("    v")

            print(
                f"{edge['destination']}"
            )

            print()


if __name__ == "__main__":

    flow = SecurityFlow()

    flow.add_edge(
        "rand()",
        "generate_iv::iv",
        "writes"
    )

    flow.add_edge(
        "generate_iv::iv",
        "main::iv",
        "aliases"
    )

    flow.add_edge(
        "main::iv",
        "aes_cbc_encrypt::iv",
        "passed as IV"
    )

    flow.add_edge(
        "aes_cbc_encrypt::iv",
        "AES-CBC",
        "cryptographic input"
    )

    flow.print_graph()