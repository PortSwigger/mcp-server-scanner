package com.mcpscanner.checks.content;

import com.mcpscanner.checks.content.rules.AiKeyRule;
import com.mcpscanner.checks.content.rules.AwsAccessKeyRule;
import com.mcpscanner.checks.content.rules.AzureConnectionStringRule;
import com.mcpscanner.checks.content.rules.CreditCardRule;
import com.mcpscanner.checks.content.rules.EmailRule;
import com.mcpscanner.checks.content.rules.GcpServiceAccountRule;
import com.mcpscanner.checks.content.rules.GithubPatRule;
import com.mcpscanner.checks.content.rules.GoogleApiKeyRule;
import com.mcpscanner.checks.content.rules.IconContentRule;
import com.mcpscanner.checks.content.rules.JwtRule;
import com.mcpscanner.checks.content.rules.PgpPrivateKeyRule;
import com.mcpscanner.checks.content.rules.PrivateIpRule;
import com.mcpscanner.checks.content.rules.SlackTokenRule;
import com.mcpscanner.checks.content.rules.SshPrivateKeyRule;
import com.mcpscanner.checks.content.rules.StripeKeyRule;

import java.util.ArrayList;
import java.util.List;

public final class ContentRules {

    private ContentRules() {}

    public static List<ContentRule> all() {
        List<ContentRule> rules = new ArrayList<>(highPrecisionSecrets());
        rules.add(new EmailRule());
        rules.add(new PrivateIpRule());
        rules.add(new CreditCardRule());
        rules.add(new IconContentRule());
        return List.copyOf(rules);
    }

    public static List<ContentRule> highPrecisionSecrets() {
        return List.of(
                new AwsAccessKeyRule(),
                new GithubPatRule(),
                new SlackTokenRule(),
                new StripeKeyRule(),
                new GoogleApiKeyRule(),
                new GcpServiceAccountRule(),
                new AzureConnectionStringRule(),
                new AiKeyRule(),
                new JwtRule(),
                new SshPrivateKeyRule(),
                new PgpPrivateKeyRule()
        );
    }
}
