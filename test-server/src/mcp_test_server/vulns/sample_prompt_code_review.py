from __future__ import annotations

from mcp_test_server.registry import PromptPlugin


class SampleCodeReview(PromptPlugin):
    name = "code_review"
    description = "Generate a code-review prompt for a snippet of code."

    async def handle_get(self, code: str, language: str) -> str:
        return (
            f"Review the following {language} code and suggest improvements:\n\n"
            f"```{language}\n{code}\n```"
        )


PLUGIN = SampleCodeReview()
