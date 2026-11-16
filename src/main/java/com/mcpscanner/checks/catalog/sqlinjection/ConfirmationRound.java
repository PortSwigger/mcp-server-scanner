package com.mcpscanner.checks.catalog.sqlinjection;

import java.util.List;

record ConfirmationRound(Probe resent, Separation repeated) {

    boolean agrees(Probe baseline) {
        return resent.shape().matches(baseline.shape()) && repeated.separates(baseline);
    }

    List<Probe> probes() {
        return List.of(resent, repeated.equivalent(), repeated.falsifier());
    }
}
