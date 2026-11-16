package com.mcpscanner.access.mining;

import java.util.List;

record CallOutcome(List<Sighting> sightings, MiningStop stop) {

    CallOutcome {
        sightings = List.copyOf(sightings);
    }
}
