package com.mcpscanner.checks.catalog.filetraversal;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class FileTraversalDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "file-traversal",
            "MCP file path traversal",
            "Sends Unix and Windows traversal paths (absolute, encoded, double-encoded, mixed-separator, "
                    + "NUL-terminated and escaping the field's own directory at several depths) and every case "
                    + "spelling of .git paths through every MCP field, host files first and strongest form first, "
                    + "stopping at the field's first confirmed whole-file read. It "
                    + "reports recognisable file content that a matched missing-file path does not return, plus "
                    + "filter bypasses and prefix-sibling root boundary failures.",
            CheckKind.INSERTION_POINT,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://portswigger.net/web-security/file-path-traversal"),
            "MCP tools, resources and prompts often take file paths from the client. When the server does not "
                    + "confine a path to its intended root, a client can read arbitrary files on the server host.",
            List.of(new Cwe(22, "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')")));

    private FileTraversalDescriptor() {
    }
}
