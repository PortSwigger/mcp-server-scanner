package com.mcpscanner.integration;

import com.mcpscanner.access.mining.MiningReport;
import com.mcpscanner.access.mining.MiningStop;
import com.mcpscanner.identity.MinedValue;
import com.mcpscanner.identity.ValueScope;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
class AccessMiningIT {

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void miningAsAliceAndBobStoresEachUsersPrivateValues() throws Exception {
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer("--default-mode", "safe");
             CollectIdsFixture collecting = CollectIdsFixture.connect(McpCheckItSupport.mcpEndpoint(server.port()))) {
            MiningReport report = collecting.collect();

            System.out.println("[access-mining-e2e] " + report.summary() + " warnings=" + report.warnings());
            print("alice", collecting.aliceValues());
            print("bob", collecting.bobValues());
            assertThat(report.stop()).isEqualTo(MiningStop.COMPLETED);
            assertThat(privateValues(collecting.aliceValues())).isNotEmpty()
                    .doesNotContainAnyElementsOf(privateValues(collecting.bobValues()));
            assertThat(privateValues(collecting.aliceValues())).contains("notes://alice/private.md");
            assertThat(privateValues(collecting.bobValues())).contains("notes://bob/private.md");
            assertThat(report.warnings()).noneMatch(line -> line.contains("another tenant"));
            assertThat(collecting.mining().minedForCurrentIdentities()).isTrue();
        }
    }

    private static List<String> privateValues(List<MinedValue> values) {
        return values.stream().filter(value -> value.scope() == ValueScope.PRIVATE).map(MinedValue::value).toList();
    }

    private static void print(String user, List<MinedValue> values) {
        values.forEach(value -> System.out.println("[access-mining-e2e] " + user + " " + value.scope() + " "
                + value.argument() + "=" + value.value() + " from " + value.source().operation() + " "
                + value.source().fieldPath()));
    }
}
