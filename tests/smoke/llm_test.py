import json
import os
import unittest
import sys
import time
from tests.smoke import smoke_utils

# We import llm_sender inside the test method or module, but we need to make sure
# dependencies are installed in the environment where this runs.
try:
    from tests.smoke import llm_sender
except ImportError:
    llm_sender = None


class LLMToolSelectionTest(unittest.TestCase):
    def setUp(self):
        if not os.environ.get("GEMINI_API_KEY"):
            self.skipTest("GEMINI_API_KEY not set")
        if llm_sender is None:
            self.fail("Could not import llm_sender. Missing dependencies?")

    def test_llm_tool_selection(self):
        """Verifies that the LLM selects the correct tool for each prompt."""
        # 1. Get tools from server
        try:
            tools_response = smoke_utils.get_tools_list()
            tools = tools_response.get("tools", [])
        except Exception as e:
            self.fail(f"Failed to get tools from server: {e}")

        if not tools:
            self.fail("No tools returned by server")

        # 2. Load test cases
        cases_path = os.path.join(os.path.dirname(__file__), "llm_cases.json")
        if not os.path.exists(cases_path):
            self.fail(f"Test cases file not found at {cases_path}")

        with open(cases_path, "r") as f:
            cases = json.load(f)

        # 3. specific test for each case
        failures = []
        for case in cases:
            prompt = case["prompt"]
            expected_tool = case["expected_tool"]

            print(
                f"Testing prompt: '{prompt}' (Expecting: {expected_tool})",
                file=sys.stderr,
            )

            try:
                selected_tool = llm_sender.get_llm_response(prompt, tools)

                if selected_tool != expected_tool:
                    failures.append(
                        f"Prompt: '{prompt}'\n  Expected: {expected_tool}\n  Got: {selected_tool}"
                    )
                else:
                    print(f"  -> Success: {selected_tool}", file=sys.stderr)

                # Sleep to avoid rate limits
                time.sleep(10)

            except Exception as e:
                failures.append(f"Prompt: '{prompt}'\n  Error: {e}")

        if failures:
            self.fail("LLM Tool Selection Failures:\n" + "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
