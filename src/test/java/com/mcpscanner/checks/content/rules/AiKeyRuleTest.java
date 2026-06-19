package com.mcpscanner.checks.content.rules;

import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AiKeyRuleTest {

    private final AiKeyRule rule = new AiKeyRule();

    @Test
    void identifiesOpenAiProjectKeyWithT3BlbkFJMarker() {
        String key = "sk-proj-abcdefghijklmnopqrstuvwxT3BlbkFJabcdefghijklmnopqrstuvwx";
        assertThat(rule.evaluate(field(key))).hasSize(1);
    }

    @Test
    void doesNotFireOnRandomShortSkLiveString() {
        // sk-live- is not a real provider prefix (real key prefixes use underscores)
        assertThat(rule.evaluate(field("sk-live-abcdefghijklmnopqrstuvwx"))).isEmpty();
    }

    @Test
    void identifiesAnthropicKeyWithApi03Marker() {
        String key = "sk-ant-api03-" + ("aB3xZ9qWmK2vL7nP1rT5yU8iO4eC6sD0fG".repeat(3)).substring(0, 93);
        assertThat(rule.evaluate(field(key))).hasSize(1);
    }

    @Test
    void doesNotFireOnLowEntropyShapedAnthropicPlaceholder() {
        // Matches the Anthropic shape but the body is a single repeated character — entropy ~0.
        assertThat(rule.evaluate(field("sk-ant-api03-" + "x".repeat(93)))).isEmpty();
    }

    @Test
    void doesNotFireOnAnthropicWithoutApi03() {
        // older sk-ant- without api03 marker no longer flagged
        assertThat(rule.evaluate(field("sk-ant-abcdefghijklmnopqrstuvwx"))).isEmpty();
    }

    @Test
    void doesNotFireOnBareSkPrefix() {
        // bare sk- without a recognised provider marker is no longer flagged
        assertThat(rule.evaluate(field("sk-abcdefghijklmnopqrstuvwx"))).isEmpty();
    }

    @Test
    void identifiesServiceAccountKeyWithT3BlbkFJMarker() {
        String key = "sk-svcacct-abcdefghijklmnopqrstuvwxT3BlbkFJabcdefghijklmnopqrstuvwx";
        assertThat(rule.evaluate(field(key))).hasSize(1);
    }

    @Test
    void suppressesExampleField() {
        InspectedField example = new InspectedField(
                SourceObjectType.TOOL, "ai_tool", "inputSchema.properties.key.example",
                "sk-proj-abcdefghijklmnopqrstuvwxT3BlbkFJabcdefghijklmnopqrstuvwx");

        assertThat(rule.evaluate(example)).isEmpty();
    }

    @Test
    void suppressesExamplesArrayField() {
        InspectedField example = new InspectedField(
                SourceObjectType.TOOL, "ai_tool", "inputSchema.properties.key.examples[0]",
                "sk-proj-abcdefghijklmnopqrstuvwxT3BlbkFJabcdefghijklmnopqrstuvwx");

        assertThat(rule.evaluate(example)).isEmpty();
    }

    @Test
    void stillFlagsRealSecretHardCodedAsDefault() {
        // A `default` is a real configured value (used when the caller omits the argument), so a
        // live secret hard-coded there is a genuine leak and must not be suppressed as an example.
        InspectedField defaultValue = new InspectedField(
                SourceObjectType.TOOL, "ai_tool", "inputSchema.properties.key.default",
                "sk-proj-abcdefghijklmnopqrstuvwxT3BlbkFJabcdefghijklmnopqrstuvwx");

        assertThat(rule.evaluate(defaultValue)).hasSize(1);
    }

    @Test
    void ignoresPlainText() {
        assertThat(rule.evaluate(field("nothing here"))).isEmpty();
    }

    @Test
    void referencesPointToFirstPartyProviderDocs() {
        assertThat(rule.metadata().references()).containsExactly(
                "https://platform.openai.com/docs/api-reference/authentication",
                "https://platform.claude.com/docs/en/api/overview");
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "ai_tool", "description", value);
    }
}
