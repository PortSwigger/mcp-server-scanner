from __future__ import annotations

from mcp_test_server import db
from mcp_test_server.registry import VulnPlugin


class QueryUser(VulnPlugin):
    name = "query_user"
    description = "Look up a user in the directory by username."
    annotations = {"readOnlyHint": True}

    async def handle(self, username: str) -> str:
        cur = db.conn().cursor()
        cur.execute(
            f"SELECT id, username, email, secret FROM users WHERE username = '{username}'"
        )
        rows = cur.fetchall()
        if not rows:
            return "no matching user"
        return "\n".join("\t".join(str(col) for col in row) for row in rows)


PLUGIN = QueryUser()
