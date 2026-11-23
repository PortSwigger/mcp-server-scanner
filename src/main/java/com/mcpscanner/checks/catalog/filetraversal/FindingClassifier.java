package com.mcpscanner.checks.catalog.filetraversal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

final class FindingClassifier {

    private static final int MAX_READS_PER_FINDING = 3;

    private record ClassifiedRead(FindingKind kind, ConfirmedRead read, Optional<TraversalAttempt> rejectedTwin) {}

    List<Finding> classify(ContentTrial trial) {
        Map<FindingKind, List<ClassifiedRead>> byKind = new LinkedHashMap<>();
        for (ConfirmedRead read : trial.confirmedReads()) {
            ClassifiedRead classified = classify(read, trial);
            byKind.computeIfAbsent(classified.kind(), kind -> new ArrayList<>()).add(classified);
        }
        if (byKind.containsKey(FindingKind.HOST_FILE_READ)) {
            byKind.remove(FindingKind.FILE_READ);
        }
        if (byKind.containsKey(FindingKind.FILE_READ) || byKind.containsKey(FindingKind.FILTER_BYPASS)
                || byKind.containsKey(FindingKind.HOST_FILE_READ)) {
            byKind.remove(FindingKind.PARTIAL_FILE_DISCLOSURE);
        }
        return byKind.entrySet().stream()
                .map(entry -> finding(entry.getKey(), entry.getValue()))
                .toList();
    }

    private static ClassifiedRead classify(ConfirmedRead read, ContentTrial trial) {
        TraversalPayload payload = read.payload();
        if (payload.file() == TargetFile.GIT_CONFIG) {
            return bypassOr(read, trial, PayloadTier.CASE_VARIANT,
                    FindingKind.RESTRICTED_PATH_BYPASS, FindingKind.REPOSITORY_METADATA_READ);
        }
        if (read.disclosure() == Disclosure.PARTIAL) {
            return new ClassifiedRead(FindingKind.PARTIAL_FILE_DISCLOSURE, read, Optional.empty());
        }
        if (payload.tier() == PayloadTier.ABSOLUTE) {
            return new ClassifiedRead(FindingKind.HOST_FILE_READ, read, Optional.empty());
        }
        return bypassOr(read, trial, PayloadTier.EVASION, FindingKind.FILTER_BYPASS, FindingKind.FILE_READ);
    }

    private static ClassifiedRead bypassOr(ConfirmedRead read, ContentTrial trial, PayloadTier bypassTier,
                                           FindingKind bypass, FindingKind otherwise) {
        if (read.payload().tier() != bypassTier || evasionOfAFileAPlainPathAlreadyRead(read, trial)) {
            return new ClassifiedRead(otherwise, read, Optional.empty());
        }
        List<TraversalAttempt> literalTwins = trial.literalTwins(read.payload());
        boolean literalRejected = !literalTwins.isEmpty()
                && literalTwins.stream().allMatch(TraversalAttempt::rejectedWithoutDisclosure);
        return literalRejected
                ? new ClassifiedRead(bypass, read, Optional.of(literalTwins.get(0)))
                : new ClassifiedRead(otherwise, read, Optional.empty());
    }

    private static boolean evasionOfAFileAPlainPathAlreadyRead(ConfirmedRead read, ContentTrial trial) {
        return read.payload().tier() == PayloadTier.EVASION && trial.confirmedReads().stream()
                .anyMatch(other -> other.payload().file() == read.payload().file()
                        && other.payload().tier() != PayloadTier.EVASION
                        && other.payload().tier() != PayloadTier.CASE_VARIANT
                        && other.disclosure() == Disclosure.FULL);
    }

    private static Finding finding(FindingKind kind, List<ClassifiedRead> reads) {
        List<ClassifiedRead> shown = reads.subList(0, Math.min(reads.size(), MAX_READS_PER_FINDING));
        List<String> rejectedLiterals = new ArrayList<>();
        List<String> observations = new ArrayList<>();
        for (ClassifiedRead classified : shown) {
            classified.rejectedTwin().ifPresent(twin -> {
                rejectedLiterals.add(twin.sentValue());
                observations.add("Rejected literal path: " + twin.sentValue());
            });
            observations.add(describe(classified.read()));
        }
        List<TraversalAttempt> attached = attached(shown.get(0));
        observations.add("Attached requests, in order: "
                + String.join(", ", attached.stream().map(TraversalAttempt::sentValue).toList()) + ".");
        return new Finding(kind, rejectedLiterals.stream().distinct().toList(), observations,
                attached.stream().map(TraversalAttempt::exchange).toList());
    }

    private static List<TraversalAttempt> attached(ClassifiedRead classified) {
        List<TraversalAttempt> attached = new ArrayList<>();
        classified.rejectedTwin().ifPresent(attached::add);
        attached.add(classified.read().candidate());
        attached.add(classified.read().missingFileTwin());
        return attached;
    }

    private static String describe(ConfirmedRead read) {
        String content = read.disclosure() == Disclosure.PARTIAL ? "the opening bytes of the " : "the ";
        return read.candidate().sentValue() + " returned " + content + read.payload().file().label()
                + "; the matched missing paths " + String.join(" and ",
                read.controls().stream().map(TraversalAttempt::sentValue).toList()) + " did not.";
    }
}
