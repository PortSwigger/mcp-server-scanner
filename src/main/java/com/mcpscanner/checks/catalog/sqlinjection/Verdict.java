package com.mcpscanner.checks.catalog.sqlinjection;

import java.util.Optional;

record Verdict(Optional<Finding> finding, Outcome outcome) {

    static final Verdict UNSTABLE = new Verdict(Optional.empty(), Outcome.UNSTABLE);
    static final Verdict BY_DESIGN = new Verdict(Optional.empty(), Outcome.BY_DESIGN);

    static Verdict confirmed(Finding finding) {
        return new Verdict(Optional.of(finding), Outcome.CONFIRMED);
    }

    enum Outcome {
        CONFIRMED, UNSTABLE, BY_DESIGN
    }
}
