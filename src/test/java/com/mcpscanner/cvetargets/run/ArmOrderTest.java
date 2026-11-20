package com.mcpscanner.cvetargets.run;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.OptionalLong;

import static org.assertj.core.api.Assertions.assertThat;

class ArmOrderTest {

    @Test
    void startsNeverMeasuredArmsHeaviestFirstThenMeasuredArmsLongestFirstKeepingDeclaredOrderOnTies() {
        Map<String, ArmEstimate> estimates = Map.of(
                "short", ArmEstimate.measured(60_000, 1),
                "new-light", ArmEstimate.unmeasured(1),
                "long", ArmEstimate.measured(900_000, 1),
                "new-heavy", ArmEstimate.unmeasured(2),
                "short-twin", ArmEstimate.measured(60_000, 2),
                "new-light-twin", ArmEstimate.unmeasured(1));
        List<String> declared = List.of("short", "new-light", "long", "new-heavy", "short-twin", "new-light-twin");

        assertThat(ArmOrder.longestFirst(declared, estimates::get))
                .containsExactly("new-heavy", "new-light", "new-light-twin", "long", "short", "short-twin");
    }

    @Test
    void startsArmsDeclaredToStartFirstBeforeEveryOtherArmLongestFirstAmongThemselves() {
        Map<String, ArmEstimate> estimates = Map.of(
                "new-heavy", ArmEstimate.unmeasured(2),
                "long", ArmEstimate.measured(900_000, 1),
                "first-short", ArmEstimate.measured(40_000, 1).startingFirst(),
                "first-longer", ArmEstimate.measured(190_000, 1).startingFirst());
        List<String> declared = List.of("new-heavy", "long", "first-short", "first-longer");

        assertThat(ArmOrder.longestFirst(declared, estimates::get))
                .containsExactly("first-longer", "first-short", "new-heavy", "long");
    }

    @Test
    void aSharedArmStartsFirstWhenAnyMemberDoes() {
        ArmEstimate shared = ArmEstimate.together(List.of(ArmEstimate.measured(100, 1),
                ArmEstimate.measured(300, 1).startingFirst()));

        assertThat(shared.startsFirst()).isTrue();
    }

    @Test
    void aSharedArmIsMeasuredOnlyWhenEveryMemberIsAndTakesItsLongestMemberAndHeaviestSlots() {
        ArmEstimate measured = ArmEstimate.together(List.of(ArmEstimate.measured(100, 1),
                ArmEstimate.measured(300, 2)));
        ArmEstimate partly = ArmEstimate.together(List.of(ArmEstimate.measured(100, 1), ArmEstimate.unmeasured(1)));

        assertThat(measured).isEqualTo(new ArmEstimate(OptionalLong.of(300), 2, false));
        assertThat(partly.ranMillis()).isEmpty();
    }
}
