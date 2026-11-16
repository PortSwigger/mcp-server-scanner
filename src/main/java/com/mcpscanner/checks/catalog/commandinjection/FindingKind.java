package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

enum FindingKind {

    SHELL_COMPUTED_RESULT(FindingKind.OS_COMMAND_INJECTION, AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
            "The field computed a unique shell arithmetic result that was absent from the baseline reply. "
                    + "The same command sent alone did not compute it, and a matched control with an inert "
                    + "suffix succeeded without it, so the value was spliced into a shell command line. A repeat "
                    + "with a fresh canary computed again while its bare command still did not."),
    SHELL_COMPUTED_RESULT_QUOTED_CONTROL(FindingKind.OS_COMMAND_INJECTION, AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            "The field computed a unique shell arithmetic result that was absent from the baseline reply. "
                    + "Argument validation rejected the matched control, so a quoted-literal control was sent: "
                    + "with the arithmetic single-quoted, the reply contained the unexpanded text that only shell "
                    + "quote removal produces, not the result. A repeat with a fresh canary computed again while its "
                    + "bare command still did not."),
    SHELL_OUT_OF_BAND(FindingKind.OS_COMMAND_INJECTION, AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
            "The field caused a Burp Collaborator interaction for a hostname that the payload split with an "
                    + "empty shell quote pair. The hostname only exists after shell quote removal, so a shell "
                    + "ran the injected command."),
    OPTION_INJECTION(FindingKind.ARGUMENT_INJECTION, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.TENTATIVE,
            "Sent in place of the field value, a standard command-line option made the reply list option names "
                    + "or a version number that the baseline reply lacked, that the same word without its leading "
                    + "dashes did not produce, and that a repeat of the option produced again. The reply depends on "
                    + "the leading dash, which is what a program parsing the value as an option would do, so a "
                    + "caller may be able to pass other options, such as ones that choose a server to contact or a "
                    + "file to write. Other dash-sensitive handling can produce the same difference: a language "
                    + "model answering about the option, or a search syntax where a leading dash excludes a term. "
                    + "Review how the tool uses this value and whether it means to pass caller-chosen options."),
    INTENDED_COMMAND(FindingKind.COMMAND_EXECUTION_ARGUMENT, AuditIssueSeverity.INFORMATION,
            AuditIssueConfidence.TENTATIVE,
            "The field computed a unique shell arithmetic result both when the command was appended to its value "
                    + "and when the bare command was sent alone, so the field itself is run as a shell command. "
                    + "Review whether running commands is intended and who can call this tool."),
    INTERPRETER_COMPUTED_RESULT(FindingKind.CODE_INJECTION, AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
            "Appending a payload that closes the surrounding string or template context to the original value "
                    + "returned a unique value that only an interpreter could decode from the character codes in "
                    + "the payload. The baseline and a matched control with an inert suffix lacked it, the decoder "
                    + "sent alone was not evaluated, and a repeat with a fresh value evaluated again, so the value "
                    + "was spliced into code."),
    EVALUATED_ARGUMENT(FindingKind.CODE_EXECUTION_ARGUMENT, AuditIssueSeverity.INFORMATION,
            AuditIssueConfidence.TENTATIVE,
            "Sent on its own in place of the field value, a payload returned a unique value that only an "
                    + "interpreter, or a component such as a language model that computes what it is given, could "
                    + "decode from its character codes; the baseline and a matched control lacked it. Because the "
                    + "bare payload is evaluated, this shows the field is evaluated as code, not that it was spliced "
                    + "into other code. Review whether running supplied code is the tool's purpose and who can call "
                    + "it.");

    static final String OS_COMMAND_INJECTION = "MCP OS command injection";
    static final String CODE_INJECTION = "MCP code injection";
    static final String ARGUMENT_INJECTION = "MCP argument injection";
    static final String CODE_EXECUTION_ARGUMENT = "MCP code execution argument";
    static final String COMMAND_EXECUTION_ARGUMENT = "MCP command execution argument";

    private final String issueName;
    private final AuditIssueSeverity severity;
    private final AuditIssueConfidence confidence;
    private final String observation;

    FindingKind(String issueName, AuditIssueSeverity severity, AuditIssueConfidence confidence, String observation) {
        this.issueName = issueName;
        this.severity = severity;
        this.confidence = confidence;
        this.observation = observation;
    }

    String issueName() {
        return issueName;
    }

    AuditIssueSeverity severity() {
        return severity;
    }

    AuditIssueConfidence confidence() {
        return confidence;
    }

    String observation() {
        return observation;
    }
}
