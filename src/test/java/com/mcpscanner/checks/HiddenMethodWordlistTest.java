package com.mcpscanner.checks;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class HiddenMethodWordlistTest {

    @Test
    void containsExactly52Probes() {
        assertThat(HiddenMethodWordlist.PROBES).hasSize(52);
    }

    @Test
    void allProbeMethodNamesAreUnique() {
        Set<String> distinct = HiddenMethodWordlist.PROBES.stream()
                .map(JsonRpcMethodProbe::methodName)
                .collect(Collectors.toSet());
        assertThat(distinct).hasSize(HiddenMethodWordlist.PROBES.size());
    }

    @Test
    void includesEachDocumentedNamespace() {
        List<String> names = HiddenMethodWordlist.PROBES.stream()
                .map(JsonRpcMethodProbe::methodName).toList();
        assertThat(names).contains("rpc.discover", "system.listMethods", "admin.config",
                "debug.info", "internal.health", "dev.debug",
                "$/cancelRequest", "debug/info", "echo", "test");
    }
}
