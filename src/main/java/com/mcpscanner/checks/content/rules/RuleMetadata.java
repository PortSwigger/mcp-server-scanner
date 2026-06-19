package com.mcpscanner.checks.content.rules;

import com.mcpscanner.checks.issue.Cwe;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;

/**
 * Shared {@link IssueMetadata} constants for content-rule categories, so the ~11 credential rules
 * (and the info-disclosure and icon rules) do not each duplicate background/remediation/CWE prose.
 * A rule with a provider-specific link keeps the shared category metadata and overrides only the
 * references via {@link IssueMetadata#withReferences(List)}.
 */
public final class RuleMetadata {

    public static final IssueMetadata CREDENTIAL = new IssueMetadata(
            "A live credential or secret is embedded in this MCP server's discovery metadata "
                    + "(server info, or a tool/resource/prompt name, description, or schema). MCP "
                    + "discovery responses are returned verbatim to every client that lists "
                    + "capabilities — often before authentication — so a secret here is effectively "
                    + "published to all callers and harvestable at scale. Treat it as compromised.",
            "Revoke and rotate the exposed credential immediately. Supply secrets from server-side "
                    + "configuration or a secrets manager at runtime; never embed them in capability "
                    + "definitions or emit them in responses.",
            List.of(
                    new Cwe(312, "Cleartext Storage of Sensitive Information"),
                    new Cwe(522, "Insufficiently Protected Credentials"),
                    new Cwe(200, "Exposure of Sensitive Information to an Unauthorized Actor")),
            List.of(),
            true);

    public static final IssueMetadata INFO_DISCLOSURE = new IssueMetadata(
            "Internal information — a personal/internal email address or an internal, loopback, or "
                    + "link-local address — appears in this server's MCP discovery metadata, which is "
                    + "returned to every client. This is not a credential, but it leaks organisational "
                    + "or network-topology detail useful for phishing or for mapping internal "
                    + "infrastructure.",
            "Replace the internal address or personal email with a generic public contact, or stop "
                    + "exposing it altogether. This is an information-disclosure issue, not a credential "
                    + "leak — no rotation is required.",
            List.of(new Cwe(200, "Exposure of Sensitive Information to an Unauthorized Actor")),
            List.of(),
            true);

    public static final IssueMetadata ICON = new IssueMetadata(
            "An icon declared in this server's MCP metadata uses an unsafe source. The MCP icon spec "
                    + "expects same-origin HTTPS raster images; a javascript:/data: scheme, an SVG "
                    + "(which can carry inline <script>), a plaintext-HTTP URL, a cross-origin host, or "
                    + "an oversized declared dimension can cause script execution in the client UI, a "
                    + "mixed-content downgrade, or fetches to attacker-influenced hosts when a client "
                    + "renders the icon.",
            "Serve icons as same-origin HTTPS raster images (PNG/WebP) with sane declared sizes. Do "
                    + "not use javascript: or data: schemes, do not ship SVG icons, and avoid "
                    + "cross-origin or plaintext-HTTP icon URLs. No credential is involved — nothing to "
                    + "revoke or rotate.",
            List.of(
                    new Cwe(79, "Improper Neutralization of Input During Web Page Generation "
                            + "('Cross-site Scripting')"),
                    new Cwe(829, "Inclusion of Functionality from Untrusted Control Sphere")),
            List.of());

    private RuleMetadata() {}
}
