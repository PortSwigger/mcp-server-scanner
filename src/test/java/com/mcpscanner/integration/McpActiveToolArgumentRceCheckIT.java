package com.mcpscanner.integration;

import com.mcpscanner.checks.McpActiveToolArgumentRceCheck;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/**
 * E2E integration test placeholder for {@link McpActiveToolArgumentRceCheck}.
 *
 * <p>The RCE check relies on Burp's {@code CollaboratorClient} to detect out-of-band
 * DNS/HTTP interactions triggered by OS command injection payloads. The Collaborator
 * infrastructure is only available inside a running Burp Suite instance and cannot be
 * replicated in a standalone JUnit process.
 *
 * <p>The check is covered by unit tests in {@code McpActiveToolArgumentRceCheckTest},
 * which stub the collaborator and assert that:
 * <ul>
 *   <li>Collaborator payloads are embedded into tool argument values.</li>
 *   <li>Collaborator interactions are collected and used to build issues.</li>
 *   <li>The check degrades gracefully when the collaborator is unavailable.</li>
 * </ul>
 */
@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
class McpActiveToolArgumentRceCheckIT {

    @Test
    @Disabled("RCE check requires Burp's Collaborator; not available in standalone E2E. "
            + "Covered by unit tests in McpActiveToolArgumentRceCheckTest.")
    void rceCheck_collaboratorRequired_skippedInE2E() {
        // Intentionally empty — this test exists to document the gap, not to run.
    }
}
