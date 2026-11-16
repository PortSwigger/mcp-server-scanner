package com.mcpscanner.access.mining;

import java.util.Set;

public record MiningSettings(int passes, int valuesPerArgument, int requestCeiling, int listPages,
                             Set<String> allowedTools) {

    public static final int MIN_PASSES = 1;
    public static final int MAX_PASSES = 5;
    public static final int DEFAULT_PASSES = 2;
    public static final int DEFAULT_VALUES_PER_ARGUMENT = 10;
    public static final int NO_REQUEST_CEILING = 0;
    public static final int DEFAULT_LIST_PAGES = 10;

    public MiningSettings {
        if (passes < MIN_PASSES || passes > MAX_PASSES) {
            throw new IllegalArgumentException("passes must be " + MIN_PASSES + " to " + MAX_PASSES + ", got " + passes);
        }
        if (valuesPerArgument < 1 || listPages < 1 || requestCeiling < NO_REQUEST_CEILING) {
            throw new IllegalArgumentException("limits must be positive");
        }
        allowedTools = Set.copyOf(allowedTools);
    }

    public static MiningSettings defaults() {
        return new MiningSettings(DEFAULT_PASSES, DEFAULT_VALUES_PER_ARGUMENT, NO_REQUEST_CEILING,
                DEFAULT_LIST_PAGES, Set.of());
    }

    public MiningSettings withPasses(int value) {
        return new MiningSettings(value, valuesPerArgument, requestCeiling, listPages, allowedTools);
    }

    public MiningSettings withAllowedTools(Set<String> tools) {
        return new MiningSettings(passes, valuesPerArgument, requestCeiling, listPages, tools);
    }

    public MiningSettings withRequestCeiling(int ceiling) {
        return new MiningSettings(passes, valuesPerArgument, ceiling, listPages, allowedTools);
    }

    boolean hasRequestCeiling() {
        return requestCeiling != NO_REQUEST_CEILING;
    }
}
