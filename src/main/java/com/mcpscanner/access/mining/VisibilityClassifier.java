package com.mcpscanner.access.mining;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.identity.MinedSource;
import com.mcpscanner.identity.MinedValue;
import com.mcpscanner.identity.ValueScope;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class VisibilityClassifier {

    private final List<IdentityRun> runs;
    private final Map<ArgumentValue, Set<String>> seenBy = new HashMap<>();
    private final Map<ArgumentValue, Set<String>> attributedTo = new HashMap<>();

    VisibilityClassifier(List<IdentityRun> runs) {
        this.runs = List.copyOf(runs);
        runs.forEach(run -> run.sightings().seen().forEach(value ->
                seenBy.computeIfAbsent(value, seen -> new HashSet<>()).add(run.identityId())));
        runs.forEach(run -> run.sightings().byArgument().forEach((argument, sightings) -> sightings.stream()
                .filter(Sighting::ownerAttributed)
                .forEach(sighting -> attributedTo.computeIfAbsent(new ArgumentValue(argument, sighting.value()),
                        value -> new HashSet<>()).add(run.identityId()))));
    }

    List<IdentityMining> identities() {
        return runs.stream().map(this::classified).toList();
    }

    List<MiningWarning> warnings() {
        List<IdentityRun> users = runs.stream().filter(run -> !Principal.isAnonymous(run.identityId())).toList();
        boolean mined = users.stream().anyMatch(run -> !valuesOf(run).isEmpty());
        boolean anyPrivate = users.stream().flatMap(run -> valuesOf(run).stream()).anyMatch(this::owned);
        return users.size() > 1 && mined && !anyPrivate ? List.of(new MiningWarning(MiningWarning.Kind.SAME_TENANT,
                null, "no user has a private value: every ID collected was seen by more than one user; add a user "
                        + "from another tenant, or give each user data of their own"))
                : List.of();
    }

    private IdentityMining classified(IdentityRun run) {
        List<MinedValue> values = new ArrayList<>();
        run.sightings().byArgument().forEach((argument, sightings) -> sightings.forEach(sighting ->
                values.add(new MinedValue(argument, sighting.value(),
                        new MinedSource(sighting.operation(), sighting.path()),
                        scope(new ArgumentValue(argument, sighting.value()), run.identityId(), sighting)))));
        return new IdentityMining(run.identityId(), values, run.requestsSent(), warnings(run, values));
    }

    private ValueScope scope(ArgumentValue value, String identityId, Sighting sighting) {
        if (privateValue(value)) {
            return ValueScope.PRIVATE;
        }
        return sighting.ownerAttributed() && attributedTo.get(value).equals(Set.of(identityId)) ? ValueScope.ATTRIBUTED : ValueScope.SHARED;
    }

    private boolean owned(ArgumentValue value) {
        return privateValue(value) || attributedTo.getOrDefault(value, Set.of()).size() == 1;
    }

    private boolean privateValue(ArgumentValue value) {
        return seenBy.getOrDefault(value, Set.of()).size() == 1;
    }

    private static List<MiningWarning> warnings(IdentityRun run, List<MinedValue> values) {
        List<MiningWarning> warnings = new ArrayList<>();
        if (values.isEmpty() && !Principal.isAnonymous(run.identityId())) {
            warnings.add(new MiningWarning(MiningWarning.Kind.EMPTY, run.identityId(),
                    "collecting found no IDs for this user, so every other user's IDs look private; give this user some data"));
        }
        run.limitWarning().ifPresent(warnings::add);
        return warnings;
    }

    private static Set<ArgumentValue> valuesOf(IdentityRun run) {
        Set<ArgumentValue> values = new HashSet<>();
        run.sightings().byArgument().forEach((argument, sightings) ->
                sightings.forEach(sighting -> values.add(new ArgumentValue(argument, sighting.value()))));
        return values;
    }
}
