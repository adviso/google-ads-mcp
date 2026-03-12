import json
import os
import sys
from tests.smoke import smoke_utils


def main():
    try:
        print("Fetching tools list from server...", file=sys.stderr)
        tools_list = smoke_utils.get_tools_list()

        # Sort tools by name to ensure deterministic output
        if "tools" in tools_list:
            tools_list["tools"].sort(key=lambda x: x.get("name", ""))

        output_path = os.path.join(
            os.path.dirname(__file__), "golden_tools_list.json"
        )

        print(f"Writing golden file to {output_path}...", file=sys.stderr)
        with open(output_path, "w") as f:
            json.dump(tools_list, f, indent=2, sort_keys=True)
            f.write("\n")  # Add trailing newline

        print("Done.", file=sys.stderr)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
