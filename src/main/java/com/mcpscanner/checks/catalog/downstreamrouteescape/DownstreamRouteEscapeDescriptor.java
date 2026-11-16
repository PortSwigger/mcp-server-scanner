package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;
import java.util.Optional;

final class DownstreamRouteEscapeDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "downstream-route-escape",
            "MCP downstream route escape",
            "Replaces each field of a successful MCP call with path traversal values and matched non-traversal "
                    + "values, and reports when the traversal values repeatably return one successful result that "
                    + "differs from the controls' result.",
            CheckKind.INSERTION_POINT,
            AuditIssueSeverity.INFORMATION,
            AuditIssueConfidence.TENTATIVE,
            true,
            List.of(),
            Optional.of("Possible MCP downstream route escape"),
            "MCP servers often wrap an HTTP API and build the downstream request path from tool arguments. When a "
                    + "value is joined into that path without encoding it as a single segment, dot segments let "
                    + "the caller move the request to other routes of the same API, which the server then calls "
                    + "with its own credentials.",
            List.of(new Cwe(22, "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')")));

    private DownstreamRouteEscapeDescriptor() {
    }
}
