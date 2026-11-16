package com.mcpscanner.checks.catalog.originhostadmission;

import com.mcpscanner.checks.api.HostSettlement;

import java.util.Optional;

record CorsReading(Optional<CorsFinding> finding, HostSettlement settlement) {

    static CorsReading found(CorsFinding finding) {
        return new CorsReading(Optional.of(finding), HostSettlement.SETTLED);
    }

    static CorsReading nothingFound(HostSettlement settlement) {
        return new CorsReading(Optional.empty(), settlement);
    }
}
