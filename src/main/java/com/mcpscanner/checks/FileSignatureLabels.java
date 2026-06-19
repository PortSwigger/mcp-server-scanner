package com.mcpscanner.checks;

import java.util.Set;
import java.util.stream.Collectors;

final class FileSignatureLabels {

    private FileSignatureLabels() {}

    static String describe(Set<FileSignature> signatures) {
        return signatures.stream()
                .map(FileSignature::humanLabel)
                .collect(Collectors.joining(" / "));
    }
}
