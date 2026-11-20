package com.mcpscanner.checks.catalog.downstreamrouteescape;

import java.util.List;

record RouteDifference(RouteProbe probe, List<SentValue> evidence, String controlSignature) {

    RouteDifference {
        evidence = List.copyOf(evidence);
    }
}
