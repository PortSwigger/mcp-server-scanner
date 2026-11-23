package com.mcpscanner.cvetargets.run;

import java.util.Comparator;
import java.util.List;
import java.util.OptionalLong;

public record ArmEstimate(OptionalLong ranMillis, int slots, boolean startsFirst) {

    static final Comparator<ArmEstimate> LONGEST_FIRST = Comparator
            .comparing((ArmEstimate estimate) -> !estimate.startsFirst())
            .thenComparing(estimate -> estimate.ranMillis().isPresent())
            .thenComparing(ArmEstimate::sizeWithinItsGroup, Comparator.reverseOrder());

    public static ArmEstimate measured(long ranMillis, int slots) {
        return new ArmEstimate(OptionalLong.of(ranMillis), slots, false);
    }

    public static ArmEstimate unmeasured(int slots) {
        return new ArmEstimate(OptionalLong.empty(), slots, false);
    }

    public static ArmEstimate together(List<ArmEstimate> members) {
        int slots = members.stream().mapToInt(ArmEstimate::slots).max().orElse(1);
        boolean allMeasured = members.stream().allMatch(member -> member.ranMillis().isPresent());
        ArmEstimate estimate = allMeasured
                ? measured(members.stream().mapToLong(member -> member.ranMillis().getAsLong()).max().orElse(0), slots)
                : unmeasured(slots);
        return members.stream().anyMatch(ArmEstimate::startsFirst) ? estimate.startingFirst() : estimate;
    }

    public ArmEstimate startingFirst() {
        return new ArmEstimate(ranMillis, slots, true);
    }

    private long sizeWithinItsGroup() {
        return ranMillis.orElse(slots);
    }
}
