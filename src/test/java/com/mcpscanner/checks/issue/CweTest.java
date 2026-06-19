package com.mcpscanner.checks.issue;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CweTest {

    @Test
    void urlPointsAtMitreDefinition() {
        assertThat(new Cwe(22, "Path Traversal").url())
                .isEqualTo("https://cwe.mitre.org/data/definitions/22.html");
    }

    @Test
    void labelCombinesIdAndTitle() {
        assertThat(new Cwe(287, "Improper Authentication").label())
                .isEqualTo("CWE-287: Improper Authentication");
    }
}
