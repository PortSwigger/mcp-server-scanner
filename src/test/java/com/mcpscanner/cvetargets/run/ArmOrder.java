package com.mcpscanner.cvetargets.run;

import java.util.Comparator;
import java.util.List;
import java.util.function.Function;

public final class ArmOrder {

    private ArmOrder() {
    }

    public static <T> List<T> longestFirst(List<T> declared, Function<T, ArmEstimate> estimate) {
        return declared.stream().sorted(Comparator.comparing(estimate, ArmEstimate.LONGEST_FIRST)).toList();
    }
}
