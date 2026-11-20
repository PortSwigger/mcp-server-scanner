package com.mcpscanner.cvetargets.run;

import com.mcpscanner.cvetargets.manifest.TargetSelection;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

class HarnessSettingsTest {

    @Test
    void keepsTheRecorderLocksBesideTheMachineSlots() {
        HarnessSettings settings = new HarnessSettings(Path.of("targets"), Path.of("results"),
                TargetSelection.everything(), 2, Path.of("/cache/mcp-cve-targets/slots"), 2, false,
                Path.of("/cache/mcp-cve-targets/durations/cveTargets.json"));

        assertThat(settings.recorderLocksDirectory()).isEqualTo(Path.of("/cache/mcp-cve-targets/recorder"));
    }

    @Test
    void keepsArmDurationsBesideTheMachineSlotsPerTaskAndConfiguration() {
        Properties properties = properties("cveTargets.slotsDir", "/cache/mcp-cve-targets/slots");
        properties.setProperty("cveTargets.results", "/work/build/cve-targets/cveTargetsBurp/extensions-only");

        assertThat(HarnessSettings.fromProperties(properties).durationsFile())
                .isEqualTo(Path.of("/cache/mcp-cve-targets/durations/cveTargetsBurp/extensions-only.json"));
    }

    @Test
    void anExplicitDurationsFileWins() {
        Properties properties = properties("cveTargets.durations", "/elsewhere/history.json");

        assertThat(HarnessSettings.fromProperties(properties).durationsFile()).isEqualTo(Path.of("/elsewhere/history.json"));
    }

    @Test
    void anExplicitParallelismRaisesTheDefaultSlotCountSoThatManyArmsCanRun() {
        HarnessSettings settings = HarnessSettings.fromProperties(properties("cveTargets.parallel", "3"));

        assertThat(settings.slots()).isEqualTo(3);
        assertThat(settings.parallelArms()).isEqualTo(3);
    }

    @Test
    void aParallelismBelowTheDefaultKeepsTheDefaultSlots() {
        HarnessSettings settings = HarnessSettings.fromProperties(properties("cveTargets.parallel", "1"));

        assertThat(settings.slots()).isEqualTo(HarnessSettings.DEFAULT_SLOTS);
        assertThat(settings.parallelArms()).isEqualTo(1);
    }

    @Test
    void explicitSlotsAreKeptEvenBelowTheParallelism() {
        Properties properties = properties("cveTargets.parallel", "3");
        properties.setProperty("cveTargets.slots", "2");

        HarnessSettings settings = HarnessSettings.fromProperties(properties);

        assertThat(settings.slots()).isEqualTo(2);
        assertThat(settings.parallelArms()).isEqualTo(3);
    }

    @Test
    void slotsAloneSetTheParallelism() {
        HarnessSettings settings = HarnessSettings.fromProperties(properties("cveTargets.slots", "4"));

        assertThat(settings.parallelArms()).isEqualTo(4);
    }

    private static Properties properties(String name, String value) {
        Properties properties = new Properties();
        properties.setProperty(name, value);
        return properties;
    }
}
