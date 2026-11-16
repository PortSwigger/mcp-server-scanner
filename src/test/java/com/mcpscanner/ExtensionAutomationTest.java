package com.mcpscanner;

import com.mcpscanner.checks.registry.CheckInstrumentation;
import com.mcpscanner.scan.request.ScanMessageRenderer;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ExtensionAutomationTest {

    @Test
    void theTestAutomationIsFoundWhenItsSourceSetIsOnTheClasspath() {
        assertThat(ExtensionAutomation.installed()).isInstanceOf(TestAutomationWiring.class);
    }

    @Test
    void withoutTheTestAutomationTheExtensionIsUninstrumentedAndRendersLaunchesUnchanged() {
        ScanMessageRenderer renderer = mock(ScanMessageRenderer.class);

        assertThat(ExtensionAutomation.NONE.instrumentation()).isSameAs(CheckInstrumentation.NONE);
        assertThat(ExtensionAutomation.NONE.launchRenderer().apply(renderer)).isSameAs(renderer);
    }
}
