package com.mcpscanner.checks;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.List;

public record DcrRedirectUriProbe(String id,
                                  String displayName,
                                  String redirectUri,
                                  AuditIssueSeverity tier) {

    public static final List<DcrRedirectUriProbe> PROBES = List.of(
            new DcrRedirectUriProbe(
                    "JAVASCRIPT_SCHEME",
                    "javascript: scheme",
                    "javascript:alert(1)",
                    AuditIssueSeverity.HIGH),
            new DcrRedirectUriProbe(
                    "DATA_SCHEME",
                    "data: scheme",
                    "data:text/html,<script>1</script>",
                    AuditIssueSeverity.HIGH),
            new DcrRedirectUriProbe(
                    "WILDCARD_HOST",
                    "wildcard host",
                    "https://*.attacker.example/cb",
                    AuditIssueSeverity.HIGH),
            new DcrRedirectUriProbe(
                    "PATH_TRAVERSAL",
                    "path-traversal in path",
                    "https://server.example/cb/../bypass",
                    AuditIssueSeverity.MEDIUM),
            new DcrRedirectUriProbe(
                    "HTTP_DOWNGRADE",
                    "http:// downgrade",
                    "http://attacker.example/cb",
                    AuditIssueSeverity.MEDIUM)
    );
}
