package com.mcpscanner.engine;

import org.junit.jupiter.api.Test;

import java.time.Clock;

import static com.mcpscanner.engine.EngineFixtures.LABEL;
import static org.assertj.core.api.Assertions.assertThat;

class EngineScanAbortTest {

    private final EngineScan scan = new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0);

    @Test
    void abortingRecordsTheReasonAsAScanErrorAndCancelsTheScan() {
        scan.abort("Connection lost: the MCP session ended");

        ScanSnapshot snapshot = scan.snapshot();
        assertThat(snapshot.errors().total()).isEqualTo(1);
        assertThat(snapshot.errors().recent().get(0).reason()).isEqualTo("Connection lost: the MCP session ended");
        assertThat(scan.cancelled()).isTrue();
    }
}
