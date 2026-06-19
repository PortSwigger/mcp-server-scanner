package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.ContentSuppression;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AzureConnectionStringRule extends RegexContentRule {

    private static final Pattern AZURE = Pattern.compile(
            "DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;[^\\s]*?AccountKey=[A-Za-z0-9+/=]{40,}");
    private static final Pattern ACCOUNT_KEY_BODY = Pattern.compile("AccountKey=([A-Za-z0-9+/=]{40,})");

    // A live 32/64-byte storage key encodes to dense random base64 (~5.5 bits/char); a shaped
    // placeholder such as a repeated character scores near zero. 3.0 sits in the empty gap.
    private static final double MIN_ACCOUNT_KEY_ENTROPY_BITS_PER_CHAR = 3.0;

    public AzureConnectionStringRule() {
        super(AZURE);
    }

    @Override
    public String id() {
        return "discovery-content-scanner.azure-connection-string";
    }

    @Override
    public String displayName() {
        return "Azure Storage Connection Strings";
    }

    @Override
    public AuditIssueSeverity severity() {
        return AuditIssueSeverity.HIGH;
    }

    @Override
    protected boolean isSuppressedMatch(String match) {
        Matcher matcher = ACCOUNT_KEY_BODY.matcher(match);
        if (!matcher.find()) {
            return false;
        }
        return ContentSuppression.shannonEntropy(matcher.group(1)) < MIN_ACCOUNT_KEY_ENTROPY_BITS_PER_CHAR;
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.CREDENTIAL.withReferences(List.of(
                "https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string"));
    }
}
