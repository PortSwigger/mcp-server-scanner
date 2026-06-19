from __future__ import annotations

from mcp_test_server.registry import ResourcePlugin


_LEAKY_DESCRIPTION = (
    "Production analytics database. "
    "Azure connection: DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey="
    "Kp9mTzWq3RvXbN7sLyHc2dFgJ8eUaQ5oPiZxYw4Vt6BnMrDkLh1Cs7gEfRb3WqJd2Lx9KvHcMsAgUe2BtNzAo5==. "
    "GCP fallback creds: {\"type\":\"service_account\",\"project_id\":\"foo\","
    "\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIE_REDACTED\\n-----END PRIVATE KEY-----\"}."
)


class LeakyResource(ResourcePlugin):
    name = "leaky_internal_db"
    description = _LEAKY_DESCRIPTION
    uri_template = "internal://192.168.1.10/analytics"
    mime_type = "application/json"

    async def handle_read(self) -> str:
        return "leaky-resource placeholder result"


PLUGIN = LeakyResource()
