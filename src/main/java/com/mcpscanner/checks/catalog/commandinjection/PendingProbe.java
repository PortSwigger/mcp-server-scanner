package com.mcpscanner.checks.catalog.commandinjection;

import com.mcpscanner.checks.shared.collaborator.ObservedInteractions;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

record PendingProbe(FieldSubject subject, Map<String, SentBreakout> sentByPayloadId) {

    PendingProbe {
        sentByPayloadId = Map.copyOf(sentByPayloadId);
    }

    Finding finding(ObservedInteractions observed) {
        List<SentBreakout> fired = firedInArrivalOrder(observed);
        return new Finding(FindingKind.SHELL_OUT_OF_BAND, subject, technique(observed, fired),
                fired.stream().limit(1).map(SentBreakout::exchange).toList(), observed.inArrivalOrder());
    }

    private List<SentBreakout> firedInArrivalOrder(ObservedInteractions observed) {
        return observed.inArrivalOrder().stream()
                .map(interaction -> sentByPayloadId.get(interaction.id().toString()))
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    private static String technique(ObservedInteractions observed, List<SentBreakout> fired) {
        return interactionTypes(observed) + attachedBreakout(fired) + alsoFired(fired);
    }

    private static String interactionTypes(ObservedInteractions observed) {
        return observed.inArrivalOrder().stream()
                .map(interaction -> String.valueOf(interaction.type()))
                .distinct()
                .sorted()
                .collect(Collectors.joining(" and ", "Collaborator ", " interaction"));
    }

    private static String attachedBreakout(List<SentBreakout> fired) {
        return fired.stream().findFirst()
                .map(first -> " from the " + first.breakout().described() + " breakout, whose request is attached")
                .orElse("");
    }

    private static String alsoFired(List<SentBreakout> fired) {
        List<String> others = fired.stream().skip(1).map(sent -> sent.breakout().described()).toList();
        return others.isEmpty() ? "" : "; the " + listed(others) + " breakouts also caused interactions";
    }

    private static String listed(List<String> names) {
        int last = names.size() - 1;
        return last == 0 ? names.get(0) : String.join(", ", names.subList(0, last)) + " and " + names.get(last);
    }
}
