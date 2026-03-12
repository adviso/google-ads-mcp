import os
import json
import sys
import time
from google.genai import types
from google.genai import Client
from google.genai import errors


def get_llm_response(prompt: str, tools: list) -> str:
    """Sends a prompt to the LLM with the given tools and returns the tool usage."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY environment variable not set.")

    client = Client(api_key=api_key)

    # Convert MCP tools to Gemini tools format if necessary, or pass as is if supported.
    # The google-genai SDK supports function calling. We need to map MCP tools to it.
    # For simplicity, we'll try to pass the tool definitions directly if they match,
    # or we might need to adapt them. MCP tools are JSON Schema.
    # Gemini expects: tool = types.Tool(function_declarations=[...])

    function_declarations = []
    for tool in tools:
        # MCP tool: {name, description, inputSchema}
        # Gemini FunctionDeclaration: {name, description, parameters}
        # Truncate description to avoid hitting token limits with massive tool docs
        description = tool.get("description", "")
        if tool["name"] == "search":
            description = "Search for Google Ads resources such as campaigns, ad groups, keywords, and metrics using Google Ads Query Language (GAQL). Use this tool to find objects by name or status."
        elif len(description) > 1024:
            description = description[:1024] + "..."

        fd = types.FunctionDeclaration(
            name=tool["name"],
            description=description,
            parameters=tool.get("inputSchema", {}),
        )
        function_declarations.append(fd)

    llm_tools = [types.Tool(function_declarations=function_declarations)]

    max_retries = 5
    base_delay = 2

    # Sleep to respect rate limits
    time.sleep(5)

    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model="gemini-flash-latest",
                contents=prompt,
                config=types.GenerateContentConfig(
                    tools=llm_tools, temperature=0.0
                ),
            )

            if not response.candidates:
                return None

            candidate = response.candidates[0]
            # Check for function calls
            for part in candidate.content.parts:
                if part.function_call:
                    return part.function_call.name

            return None

        except errors.ClientError as e:
            if e.code == 429:
                if attempt < max_retries - 1:
                    delay = base_delay * (2**attempt)
                    print(
                        f"Rate limited. Retrying in {delay} seconds...",
                        file=sys.stderr,
                    )
                    time.sleep(delay)
                    continue
            raise e
