package com.mcpscanner.cvetargets.burp;

import com.mcpscanner.automation.AuditPathCanaryCommand;
import com.mcpscanner.automation.AuditPathCanaryReport;
import com.mcpscanner.cvetargets.environment.Pause;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@Tag("burp-canary")
class BurpAuditPathWriteCanaryTest {

    private static HeadlessBurpSession burp;
    private static IdleClosingOrigin origin;

    @BeforeAll
    static void startBurpAndOrigin() {
        origin = IdleClosingOrigin.start();
        burp = new HeadlessBurpLauncher(BurpSettings.fromSystemProperties(), Pause.sleeping())
                .start("audit-path-write-canary", origin.url(), () -> false);
    }

    @AfterAll
    static void stopBurpAndOrigin() {
        if (burp != null) {
            burp.close();
        }
        origin.close();
    }

    @Test
    void aWriteThroughTheScannersHttpAfterExtensionTrafficOnTheSameOriginIsAnswered() {
        AuditPathCanaryReport report = burp.automation().auditPathCanary(new AuditPathCanaryCommand(origin.url()));

        assertThat(report.extensionSendsUnanswered()).isZero();
        assertThat(origin.idleClosed()).as("connections the origin closed while idle").isPositive();
        assertThat(report.writeAnswered()).isTrue();
    }
}
