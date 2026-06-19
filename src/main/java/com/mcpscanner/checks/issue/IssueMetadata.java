package com.mcpscanner.checks.issue;

import java.util.List;

/**
 * Issue background/remediation/CWE/reference metadata shared by content rules and reporters.
 *
 * <p>{@code surfaceSpecificRemediation} marks a remediation as location-agnostic: the base prose
 * states only the rotation/principle, and the caller appends a surface-specific clause (discovery
 * vs runtime response) describing <em>where</em> the value must be removed. Rules whose remediation
 * is already self-contained (e.g. icon guidance) leave it {@code false}.
 */
public record IssueMetadata(String background,
                            String remediation,
                            List<Cwe> cwes,
                            List<String> references,
                            boolean surfaceSpecificRemediation) {

    public IssueMetadata(String background, String remediation, List<Cwe> cwes, List<String> references) {
        this(background, remediation, cwes, references, false);
    }

    public IssueMetadata {
        cwes = List.copyOf(cwes);
        references = List.copyOf(references);
    }

    public IssueMetadata withReferences(List<String> references) {
        return new IssueMetadata(background, remediation, cwes, references, surfaceSpecificRemediation);
    }
}
