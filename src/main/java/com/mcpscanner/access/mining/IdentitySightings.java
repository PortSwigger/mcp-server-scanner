package com.mcpscanner.access.mining;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class IdentitySightings {

    private final int valuesPerArgument;
    private final Map<String, Map<String, Sighting>> byArgument = new LinkedHashMap<>();
    private final Set<ArgumentValue> seen = new LinkedHashSet<>();

    IdentitySightings(int valuesPerArgument) {
        this.valuesPerArgument = valuesPerArgument;
    }

    int add(List<Sighting> sightings) {
        int added = 0;
        for (Sighting sighting : sightings) {
            for (String argument : sighting.arguments()) {
                seen.add(new ArgumentValue(argument, sighting.value()));
                added += kept(argument, sighting) ? 1 : 0;
            }
        }
        return added;
    }

    Set<ArgumentValue> seen() {
        return Set.copyOf(seen);
    }

    List<Sighting> feedableFor(ArgumentSlot slot) {
        return all().stream()
                .filter(Sighting::feedable)
                .filter(sighting -> slot.takes(sighting.aliases(), sighting.node()))
                .filter(new DistinctValues()::firstSeen)
                .limit(valuesPerArgument)
                .toList();
    }

    List<String> listedResources() {
        return all().stream().filter(sighting -> sighting.kind() == Sighting.Kind.LISTED_RESOURCE)
                .map(Sighting::value).distinct().toList();
    }

    Map<String, List<Sighting>> byArgument() {
        Map<String, List<Sighting>> copy = new LinkedHashMap<>();
        byArgument.forEach((argument, values) -> copy.put(argument, List.copyOf(values.values())));
        return copy;
    }

    private boolean kept(String argument, Sighting sighting) {
        Map<String, Sighting> values = byArgument.computeIfAbsent(argument, name -> new LinkedHashMap<>());
        Sighting existing = values.get(sighting.value());
        if (existing != null) {
            if (sighting.ownerAttributed() && !existing.ownerAttributed()) {
                values.put(sighting.value(), existing.attributedTo(true));
            }
            return false;
        }
        if (values.size() >= valuesPerArgument) {
            return false;
        }
        values.put(sighting.value(), sighting);
        return true;
    }

    private List<Sighting> all() {
        return byArgument.values().stream().flatMap(values -> values.values().stream()).toList();
    }

    private static final class DistinctValues {
        private final Set<String> seen = new HashSet<>();

        boolean firstSeen(Sighting sighting) {
            return seen.add(sighting.value());
        }
    }
}
