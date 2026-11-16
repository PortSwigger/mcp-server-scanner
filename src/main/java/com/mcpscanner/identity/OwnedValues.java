package com.mcpscanner.identity;

import com.mcpscanner.checks.api.OwnedObjects;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public record OwnedValues(List<OwnedValue> all) {

    public static final OwnedValues NONE = new OwnedValues(List.of());

    public OwnedValues {
        all = all == null ? List.of() : List.copyOf(all);
    }

    public static OwnedValues of(List<? extends OwnedValue> values) {
        return new OwnedValues(List.copyOf(values));
    }

    public static OwnedValues entered(Map<String, String> arguments) {
        return of(arguments.entrySet().stream()
                .map(argument -> new EnteredValue(argument.getKey(), argument.getValue()))
                .toList());
    }

    public List<EnteredValue> entered() {
        return all.stream().filter(EnteredValue.class::isInstance).map(EnteredValue.class::cast).toList();
    }

    public List<MinedValue> mined() {
        return all.stream().filter(MinedValue.class::isInstance).map(MinedValue.class::cast).toList();
    }

    public OwnedValues withMined(List<MinedValue> mined) {
        return of(Stream.<OwnedValue>concat(entered().stream(), mined.stream()).toList());
    }

    public OwnedValues withEntered(List<EnteredValue> entered) {
        return of(Stream.<OwnedValue>concat(entered.stream(), mined().stream()).toList());
    }

    public OwnedValues withoutMined() {
        return withMined(List.of());
    }

    public OwnedObjects ownerArguments() {
        return new OwnedObjects(firstPerArgument(entered().stream()), firstPerArgument(mined().stream().filter(MinedValue::isOwned)));
    }

    private static Map<String, String> firstPerArgument(Stream<? extends OwnedValue> values) {
        Map<String, String> arguments = new LinkedHashMap<>();
        values.forEach(owned -> arguments.putIfAbsent(owned.argument(), owned.value()));
        return arguments;
    }

    public boolean isEmpty() {
        return all.isEmpty();
    }
}
