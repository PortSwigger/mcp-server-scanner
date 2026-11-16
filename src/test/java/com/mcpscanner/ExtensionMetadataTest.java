package com.mcpscanner;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ExtensionMetadataTest {

    @Test
    void nameIsTheExpectedExtensionName() {
        assertThat(ExtensionMetadata.NAME).isEqualTo("MCP Server Scanner");
    }

    @Test
    void scannerClientNameIsTheExtensionName() {
        assertThat(ExtensionMetadata.SCANNER_CLIENT_NAME).isEqualTo(ExtensionMetadata.NAME);
    }

    @Test
    void versionIsNonBlankAndFallsBackToGradleVersionWhenUnpackaged() {
        assertThat(ExtensionMetadata.VERSION).isNotBlank();
        // In the test/IDE context the class is not loaded from the fat JAR, so the
        // manifest implementation version is absent and VERSION uses the fallback.
        assertThat(ExtensionMetadata.VERSION).isEqualTo("2.1.2");
    }
}
