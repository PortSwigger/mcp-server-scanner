package com.mcpscanner.checks.catalog.sqlinjection;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class SqlInjectionDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "sql-injection",
            "MCP SQL injection",
            "Rewrites every MCP field, and each segment of a URI value, with SQL syntax that leaves a spliced "
                    + "statement unchanged (an inline comment, a closing quote and a line comment, identifier "
                    + "quoting) and with a falsifier made of the same characters that breaks it. It reports a field "
                    + "only when the equivalent form reproduces the baseline reply, the falsifier changes it, the "
                    + "baseline is stable and a repeat with a fresh token agrees. A field that runs a whole SQL "
                    + "statement by design is not reported.",
            CheckKind.INSERTION_POINT,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://portswigger.net/web-security/sql-injection",
                    "https://cwe.mitre.org/data/definitions/89.html",
                    "https://modelcontextprotocol.io/specification/2025-06-18/server/tools#security-considerations"),
            "Database MCP servers often build SQL from tool arguments and resource URIs, typically table, column "
                    + "or database names that cannot be bound as parameters. When a server splices such a value "
                    + "into a statement, any client that can send the request, including an agent steered by "
                    + "untrusted content, can change the statement: read other tables, bypass a read-only mode or "
                    + "modify data.",
            List.of(new Cwe(89, "Improper Neutralization of Special Elements used in an SQL Command "
                    + "('SQL Injection')")));

    private SqlInjectionDescriptor() {
    }
}
