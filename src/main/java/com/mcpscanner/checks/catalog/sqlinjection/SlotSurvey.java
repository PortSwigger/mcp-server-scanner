package com.mcpscanner.checks.catalog.sqlinjection;

import java.util.List;
import java.util.Optional;

record SlotSurvey(ValueSlot slot, List<Separation> separations) {

    SlotSurvey {
        separations = List.copyOf(separations);
    }

    Optional<Separation> sqlSpecific() {
        return separations.stream().filter(separation -> separation.form().family().sqlSpecific()).findFirst();
    }

    boolean independentlyCorroborated() {
        return separations.stream().map(separation -> separation.form().family()).distinct().count() >= 2;
    }
}
