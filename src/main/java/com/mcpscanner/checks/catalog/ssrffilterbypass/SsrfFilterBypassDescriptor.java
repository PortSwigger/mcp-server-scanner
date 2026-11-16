package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class SsrfFilterBypassDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "ssrf-filter-bypass",
            "MCP SSRF address filter bypass",
            "In the URL argument of fetch, browse and scrape tools, confirms that a loopback URL is refused, "
                    + "then sends loopback in alternate address spellings (IPv4-mapped IPv6, hexadecimal, "
                    + "decimal, octal and shortened IPv4). Reports a spelling whose reply is no longer "
                    + "the refusal when the same spelling of the Burp Collaborator address is fetched.",
            CheckKind.INSERTION_POINT,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses",
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices",
                    "https://url.spec.whatwg.org/#concept-ipv4-parser"),
            "MCP tools that fetch a caller's URL often refuse private, loopback and link-local destinations so "
                    + "callers cannot reach internal services or cloud metadata. Such filters commonly compare the "
                    + "host as written against a list of private ranges, while the HTTP client parses the same "
                    + "host into an address with different rules. An address the filter does not recognise, such "
                    + "as ::ffff:7f00:1 or 2130706433, still connects to loopback, so the filter only appears to "
                    + "protect internal destinations.",
            List.of(new Cwe(918, "Server-Side Request Forgery (SSRF)")));

    private SsrfFilterBypassDescriptor() {
    }
}
