package com.mcpscanner.cvetargets;

import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.TargetManifest;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

final class TargetKnowledgeScanner {

    private static final int MINIMUM_TOKEN_LENGTH = 5;
    private static final Set<String> GENERIC_TOKENS = Set.of("server", "check", "target", "fixed", "vulnerable", "benign", "oauth",
            "provider", "bridge", "everything", "route", "network", "package", "token", "reader", "service");

    private final Set<String> identifiers;

    TargetKnowledgeScanner(List<LoadedTarget> targets) {
        this.identifiers = targets.stream()
                .flatMap(target -> identifiersOf(target.manifest()))
                .map(identifier -> identifier.toLowerCase(Locale.ROOT))
                .filter(identifier -> identifier.length() >= MINIMUM_TOKEN_LENGTH)
                .filter(identifier -> !GENERIC_TOKENS.contains(identifier))
                .collect(Collectors.toUnmodifiableSet());
    }

    Set<String> identifiers() {
        return identifiers;
    }

    List<String> namedIn(String source) {
        String text = source.toLowerCase(Locale.ROOT);
        return identifiers.stream().filter(text::contains).sorted().toList();
    }

    private static Stream<String> identifiersOf(TargetManifest manifest) {
        return Stream.of(
                        Stream.of(manifest.check(), manifest.id(), manifest.product()),
                        tokens(manifest.id()), tokens(manifest.product()),
                        manifest.advisories().stream(),
                        manifest.advisories().stream().map(advisory -> advisory.replaceFirst("^(CVE|GHSA)-", "")),
                        manifest.seeds().stream().map(seed -> seed.params() == null ? "" : seed.params().path("name").asText()))
                .flatMap(identifiers -> identifiers);
    }

    private static Stream<String> tokens(String identifier) {
        return Stream.of(identifier.split("-"));
    }
}
