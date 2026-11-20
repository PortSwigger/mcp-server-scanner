package com.mcpscanner.ui;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.MinedArguments;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class CheckAccessWriteWordingTest {

    private static final List<McpToolDefinition> WRITES = List.of(new McpToolDefinition("delete_invoice", "",
            "{\"type\":\"object\"}"));

    private final CheckAccessWriteWording wording = new CheckAccessWriteWording();

    @Test
    void theConfirmationNamesEveryPrincipalAWriteIsReplayedAs() {
        DestructiveScanPrompt prompt = mock(DestructiveScanPrompt.class);
        ArgumentCaptor<DestructiveScanConfirmation.Lines> lines =
                ArgumentCaptor.forClass(DestructiveScanConfirmation.Lines.class);

        wording.ask(prompt, null, WRITES, 1);

        verify(prompt).askLines(any(), lines.capture());
        assertThat(lines.getValue().lead()).contains("every compared user", Principal.ANONYMOUS_NAME,
                Principal.FAKE_TOKEN_NAME);
    }

    @Test
    void theCollectedValuesConfirmationNamesEveryPrincipalAWriteIsReplayedAs() {
        DestructiveScanConfirmation.Lines lines = wording.minedLines(WRITES, 1, MinedArguments.NONE);

        assertThat(lines.lead()).contains("every compared user", Principal.ANONYMOUS_NAME,
                Principal.FAKE_TOKEN_NAME);
    }
}
