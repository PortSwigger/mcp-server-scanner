package com.mcpscanner.checks.catalog.ssrffilterbypass;

import java.util.Optional;

record Refusal(SentUrl evidence, String signature) {

    static Optional<Refusal> confirmedBy(SentUrl first, SentUrl second) {
        return first.signature().filter(signature -> second.signature().filter(signature::equals).isPresent())
                .map(signature -> new Refusal(first, signature));
    }

    boolean repeatedBy(SentUrl sent) {
        return sent.signature().filter(signature::equals).isPresent();
    }
}
