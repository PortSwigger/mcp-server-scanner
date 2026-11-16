package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class CommandInjectionDescriptor {

    private static final String ID = "command-injection";

    private static final List<String> REFERENCES = List.of(
            "https://portswigger.net/web-security/os-command-injection",
            "https://modelcontextprotocol.io/specification/2025-06-18/server/tools#security-considerations",
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://cwe.mitre.org/data/definitions/94.html");

    private static final List<Cwe> CWES = List.of(
            new Cwe(78, "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"),
            new Cwe(94, "Improper Control of Generation of Code ('Code Injection')"));

    private static final String BACKGROUND = "MCP servers often wrap command-line tools and interpreters. When a "
            + "server splices a request value into a shell command line or passes it to an evaluator, any client "
            + "that can send that request runs commands or code as the server's own user.";

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            ID,
            "MCP command injection",
            "Sends shell arithmetic, interpreter character-code, command-line option and Burp Collaborator "
                    + "payloads to every MCP field, and reports a field only when the reply contains a uniquely "
                    + "computed result, or option names or a version number that an option disclosed, that its "
                    + "baseline and controls lack, or when a shell-reconstructed Collaborator hostname is contacted.",
            CheckKind.INSERTION_POINT,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            true,
            REFERENCES,
            BACKGROUND,
            CWES);

    private CommandInjectionDescriptor() {
    }
}
