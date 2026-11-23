package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;

import java.util.Optional;

final class BurpEdition {

    private static final String PRO_FEATURES = "scanning, Check access and Collect IDs";

    private final Optional<BurpSuiteEdition> edition;

    private BurpEdition(Optional<BurpSuiteEdition> edition) {
        this.edition = edition;
    }

    static BurpEdition of(MontoyaApi api) {
        return new BurpEdition(readEdition(api));
    }

    private static Optional<BurpSuiteEdition> readEdition(MontoyaApi api) {
        try {
            return Optional.ofNullable(api.burpSuite().version()).map(version -> version.edition());
        } catch (RuntimeException unreadable) {
            return Optional.empty();
        }
    }

    boolean scanningAvailable() {
        return edition.filter(BurpSuiteEdition.PROFESSIONAL::equals).isPresent();
    }

    String loadMessage() {
        return "Burp Suite " + editionName() + ": " + PRO_FEATURES + " are "
                + (scanningAvailable() ? "enabled" : "disabled");
    }

    private String editionName() {
        return edition.map(BurpSuiteEdition::displayName).orElse("of an unknown edition");
    }
}
