package com.mcpscanner.checks.catalog.ssrffilterbypass;

import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SsrfFilterBypassCheckFactoryTest {

    @Test
    void isDiscoveredAsAnInsertionPointCheckThatReadsReplies() {
        McpCheck check = CheckCatalog.discover(CheckServices.standalone()).find("ssrf-filter-bypass").orElseThrow();

        assertThat(check).isInstanceOf(SsrfFilterBypassCheck.class);
        assertThat(check.descriptor().kind()).isEqualTo(CheckKind.INSERTION_POINT);
        assertThat(check.descriptor().defaultEnabled()).isTrue();
        assertThat(check.requiresReply()).isTrue();
    }
}
