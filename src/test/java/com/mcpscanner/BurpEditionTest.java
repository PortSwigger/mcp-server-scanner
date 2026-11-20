package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BurpEditionTest {

    @Test
    void professionalUnlocksScanning() {
        assertThat(editionOf(BurpSuiteEdition.PROFESSIONAL).scanningAvailable()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = BurpSuiteEdition.class, names = {"COMMUNITY_EDITION", "ENTERPRISE_EDITION"})
    void everyOtherEditionLeavesScanningLocked(BurpSuiteEdition edition) {
        assertThat(editionOf(edition).scanningAvailable()).isFalse();
    }

    @Test
    void anUnreadableEditionLeavesScanningLocked() {
        MontoyaApi api = mock(MontoyaApi.class);
        when(api.burpSuite()).thenThrow(new IllegalStateException("unavailable"));

        assertThat(BurpEdition.of(api).scanningAvailable()).isFalse();
    }

    @Test
    void professionalSaysScanningIsEnabled() {
        assertThat(editionOf(BurpSuiteEdition.PROFESSIONAL).loadMessage())
                .isEqualTo("Burp Suite Professional: scanning, Check access and Collect IDs are enabled");
    }

    @Test
    void communitySaysScanningIsDisabled() {
        assertThat(editionOf(BurpSuiteEdition.COMMUNITY_EDITION).loadMessage())
                .isEqualTo("Burp Suite Community Edition: scanning, Check access and Collect IDs are disabled");
    }

    private static BurpEdition editionOf(BurpSuiteEdition edition) {
        MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
        when(api.burpSuite().version().edition()).thenReturn(edition);
        return BurpEdition.of(api);
    }
}
