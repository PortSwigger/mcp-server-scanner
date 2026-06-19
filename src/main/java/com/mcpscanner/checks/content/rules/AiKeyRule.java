package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;
import java.util.regex.Pattern;

public final class AiKeyRule extends HighEntropyCredentialRule {

    private static final Pattern OPENAI_PROJECT_KEY = Pattern.compile(
            "sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,74}T3BlbkFJ[A-Za-z0-9_-]{20,74}");
    private static final Pattern ANTHROPIC_API_KEY = Pattern.compile(
            "sk-ant-api03-[A-Za-z0-9_-]{93,}");

    public AiKeyRule() {
        super(OPENAI_PROJECT_KEY, ANTHROPIC_API_KEY);
    }

    @Override
    public String id() {
        return "discovery-content-scanner.ai-key";
    }

    @Override
    public String displayName() {
        return "AI Provider Keys";
    }

    @Override
    public AuditIssueSeverity severity() {
        return AuditIssueSeverity.HIGH;
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.CREDENTIAL.withReferences(List.of(
                "https://platform.openai.com/docs/api-reference/authentication",
                "https://platform.claude.com/docs/en/api/overview"));
    }
}
