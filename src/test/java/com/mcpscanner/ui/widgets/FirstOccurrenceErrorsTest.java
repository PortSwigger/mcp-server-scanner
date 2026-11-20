package com.mcpscanner.ui.widgets;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FirstOccurrenceErrorsTest {

    private final List<Throwable> errors = new ArrayList<>();
    private final List<String> debug = new ArrayList<>();
    private final FirstOccurrenceErrors log = new FirstOccurrenceErrors((message, failure) -> errors.add(failure),
            debug::add);

    @Test
    void aFailureRepeatedEveryPollIsAnErrorOnceThenDebug() {
        log.report("poll failed", new IllegalStateException("audit deleted"));
        log.report("poll failed", new IllegalStateException("audit deleted"));
        log.report("poll failed", new IllegalStateException("audit deleted"));

        assertThat(errors).singleElement().isInstanceOf(IllegalStateException.class);
        assertThat(debug).hasSize(2).allSatisfy(line -> assertThat(line).contains("poll failed"));
    }

    @Test
    void aDifferentFailureIsAnErrorAgain() {
        log.report("poll failed", new IllegalStateException("audit deleted"));
        log.report("poll failed", new IllegalArgumentException("bad row"));
        log.report("poll failed", new IllegalStateException("audit deleted"));

        assertThat(errors).hasSize(3);
        assertThat(debug).isEmpty();
    }
}
