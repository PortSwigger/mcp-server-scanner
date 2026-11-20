package com.mcpscanner.cvetargets.manifest;

import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public final class TargetManifestValidator {

    private static final Pattern IDENTIFIER = Pattern.compile("[a-z0-9][a-z0-9-]*");
    private static final Pattern ADVISORY = Pattern.compile("CVE-\\d{4}-\\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}");

    private final IdentitySetupValidator identitySetupValidator = new IdentitySetupValidator();
    private final DownloadsValidator downloadsValidator = new DownloadsValidator();
    private final SignedInSessionValidator signedInSessionValidator = new SignedInSessionValidator();

    public List<String> violations(LoadedTarget target) {
        List<String> violations = new ArrayList<>();
        TargetManifest manifest = target.manifest();
        checkIdentity(target, violations);
        checkProvenance(manifest, violations);
        checkComposeFile(target, violations);
        checkAuth(manifest.auth(), violations);
        checkSeeds(manifest.seeds(), violations);
        checkReadTimeout(manifest, violations);
        checkArms(manifest, violations);
        identitySetupValidator.check(target, violations);
        signedInSessionValidator.check(target, violations);
        downloadsValidator.check(manifest.downloads(), violations);
        return violations;
    }

    private static void checkIdentity(LoadedTarget target, List<String> violations) {
        TargetManifest manifest = target.manifest();
        if (manifest.schemaVersion() != TargetManifest.CURRENT_SCHEMA_VERSION) {
            violations.add("schemaVersion must be " + TargetManifest.CURRENT_SCHEMA_VERSION);
        }
        requireIdentifier("id", manifest.id(), violations);
        requireIdentifier("check", manifest.check(), violations);
        requireText("product", manifest.product(), violations);
        if (!target.directory().getFileName().toString().equals(manifest.id())) {
            violations.add("id must equal the target directory name " + target.directory().getFileName());
        }
        if (!target.directory().getParent().getFileName().toString().equals(manifest.check())) {
            violations.add("check must equal the check directory name " + target.directory().getParent().getFileName());
        }
    }

    private static void checkProvenance(TargetManifest manifest, List<String> violations) {
        if (manifest.source() == null || isBlank(manifest.source().repository())) {
            violations.add("source.repository is required");
        }
        manifest.advisories().stream()
                .filter(advisory -> advisory == null || !ADVISORY.matcher(advisory).matches())
                .forEach(advisory -> violations.add("advisory " + advisory + " is not a CVE or GHSA id"));
        if (!manifest.benign() && manifest.advisories().isEmpty()) {
            violations.add("a non-benign target needs at least one CVE or GHSA id");
        }
    }

    private static void checkComposeFile(LoadedTarget target, List<String> violations) {
        if (!target.composeFile().normalize().startsWith(target.directory().normalize())) {
            violations.add("compose file must live inside the target directory");
        } else if (!Files.isRegularFile(target.composeFile())) {
            violations.add("compose file " + target.manifest().compose() + " does not exist");
        }
    }

    private static void checkAuth(AuthSetup auth, List<String> violations) {
        if (auth.scheme() == null) {
            violations.add("auth.scheme is required");
            return;
        }
        if (auth.needsToken() && auth.token() == null) {
            violations.add("auth.token is required for scheme " + auth.scheme());
        }
        if (auth.token() != null) {
            violations.addAll(auth.token().violations());
        }
        if (auth.needsHeaderName() && isBlank(auth.header())) {
            violations.add("auth.header is required for scheme HEADER");
        }
        if (!auth.needsHeaderName() && auth.header() != null) {
            violations.add("auth.header applies only to scheme HEADER");
        }
        checkHeaders("auth.headers", auth.headers(), violations);
        if (auth.needsToken() && isBlank(auth.obtain())) {
            violations.add("auth.obtain must say how the credential is obtained");
        }
    }

    private static void checkHeaders(String field, Map<String, String> headers, List<String> violations) {
        if (AuthSetup.namesAuthorization(headers)) {
            violations.add(field + " must not set Authorization; use a token scheme");
        }
        headers.forEach((name, value) -> {
            if (isBlank(name) || !name.matches("[A-Za-z0-9!#$%&'*+.^_`|~-]+") || value == null
                    || value.contains("\r") || value.contains("\n")) {
                violations.add(field + " has an invalid header: " + name);
            }
        });
    }

    private static void checkSeeds(List<SeedRequest> seeds, List<String> violations) {
        seeds.stream()
                .filter(seed -> isBlank(seed.method()))
                .forEach(seed -> violations.add("every seed needs a method"));
    }

    private static void checkReadTimeout(TargetManifest manifest, List<String> violations) {
        if (manifest.readTimeoutSeconds() <= 0) {
            violations.add("readTimeoutSeconds must be above 0");
        }
        if (manifest.armTimeoutSeconds() <= 0) {
            violations.add("armTimeoutSeconds must be above 0");
        }
        if (manifest.footprintMb() <= 0) {
            violations.add("footprintMb must be above 0");
        }
        if (manifest.maxCatalogItems() <= 0) {
            violations.add("maxCatalogItems must be above 0");
        }
    }

    private static void checkArms(TargetManifest manifest, List<String> violations) {
        if (manifest.arms().isEmpty()) {
            violations.add("at least one arm is required");
            return;
        }
        Set<String> names = new HashSet<>();
        for (TargetArm arm : manifest.arms()) {
            if (!names.add(String.valueOf(arm.name()))) {
                violations.add("arm name " + arm.name() + " is duplicated");
            }
            checkArm(arm, violations);
            checkReadinessSuitsTransport(manifest.readiness(), arm, violations);
        }
        checkRoles(manifest, violations);
        checkReadinessCall(manifest.readiness(), violations);
    }

    private static void checkReadinessCall(ReadinessSpec readiness, List<String> violations) {
        readiness.authenticatedCall().ifPresent(call -> {
            if (call.method() == null || call.method().isBlank()) {
                violations.add("readiness.call.method is required");
            }
            if (readiness.probe() != ReadinessProbeType.MCP_INITIALIZE) {
                violations.add("readiness.call needs readiness probe " + ReadinessProbeType.MCP_INITIALIZE);
            }
        });
    }

    private static void checkArm(TargetArm arm, List<String> violations) {
        checkHeaders("arm " + arm.name() + ": headers", arm.headers(), violations);
        String prefix = "arm " + arm.name() + ": ";
        requireIdentifier(prefix + "name", arm.name(), violations);
        requireText(prefix + "service", arm.service(), violations);
        requireText(prefix + "version", arm.version(), violations);
        requireText(prefix + "pin", arm.pin(), violations);
        if (arm.role() == null) {
            violations.add(prefix + "role is required");
        }
        if (arm.endpoint() == null || arm.endpoint().port() < 1 || arm.endpoint().port() > 65535) {
            violations.add(prefix + "endpoint.port must be a container port");
        }
        if (arm.endpoint() == null || arm.endpoint().path() == null || !arm.endpoint().path().startsWith("/")) {
            violations.add(prefix + "endpoint.path must start with /");
        }
        if (arm.expected() == null || arm.expected().outcome() == null) {
            violations.add(prefix + "expected.outcome is required");
        } else {
            checkKnownMiss(arm, prefix, violations);
            checkKnownFlaky(arm, prefix, violations);
            checkSeverityFloor(arm.expected(), prefix, violations);
            checkDeclaredIssues(arm.expected(), prefix, violations);
        }
    }

    private static void checkDeclaredIssues(ExpectedOutcome expected, String prefix, List<String> violations) {
        if (expected.alsoReports().stream().anyMatch(name -> name == null || name.isBlank())) {
            violations.add(prefix + "alsoReports names must not be blank");
        }
        if (expected.issueName() != null && expected.declares(expected.issueName())) {
            violations.add(prefix + "alsoReports must not repeat expected.issueName " + expected.issueName());
        }
    }

    private static void checkSeverityFloor(ExpectedOutcome expected, String prefix, List<String> violations) {
        if (expected.minimumSeverity() == null) {
            return;
        }
        if (!SeverityRank.isRanked(expected.minimumSeverity())) {
            violations.add(prefix + "minimumSeverity must be INFORMATION, LOW, MEDIUM or HIGH");
        }
        if (expected.severity() != null) {
            violations.add(prefix + "give severity or minimumSeverity, not both");
        }
    }

    private static void checkKnownFlaky(TargetArm arm, String prefix, List<String> violations) {
        ExpectedOutcome expected = arm.expected();
        if (!expected.isKnownFlaky()) {
            return;
        }
        if (expected.knownFlaky().isBlank()) {
            violations.add(prefix + "knownFlaky must give the reason");
        }
        if (expected.outcome() != Outcome.FIRE) {
            violations.add(prefix + "knownFlaky applies only to a fire arm");
        }
    }

    private static void checkKnownMiss(TargetArm arm, String prefix, List<String> violations) {
        ExpectedOutcome expected = arm.expected();
        if (!expected.isKnownMiss()) {
            return;
        }
        if (expected.knownMiss().isBlank()) {
            violations.add(prefix + "knownMiss must give the reason");
        }
        if (expected.outcome() != Outcome.SILENT || arm.role() == ArmRole.BENIGN) {
            violations.add(prefix + "knownMiss applies only to a silent vulnerable or fixed arm");
        }
    }

    private static void checkReadinessSuitsTransport(ReadinessSpec readiness, TargetArm arm, List<String> violations) {
        if (readiness.probe() != arm.transport().readinessProbe()) {
            violations.add("arm " + arm.name() + ": transport " + arm.transport()
                    + " needs readiness probe " + arm.transport().readinessProbe());
        }
    }

    private static void checkRoles(TargetManifest manifest, List<String> violations) {
        if (manifest.benign()) {
            manifest.arms().stream()
                    .filter(arm -> arm.role() != ArmRole.BENIGN || !expects(arm, Outcome.SILENT) || hasExactIssueFilter(arm))
                    .forEach(arm -> violations.add("arm " + arm.name()
                            + ": a benign target's arms must be benign and silent, filtered by minimumSeverity at most"));
        } else if (manifest.arms().stream().noneMatch(arm -> arm.role() == ArmRole.VULNERABLE)) {
            violations.add("a non-benign target needs a vulnerable arm");
        }
    }

    private static boolean hasExactIssueFilter(TargetArm arm) {
        ExpectedOutcome expected = arm.expected();
        return expected.issueName() != null || expected.severity() != null || expected.confidence() != null;
    }

    private static boolean expects(TargetArm arm, Outcome outcome) {
        return arm.expected() != null && arm.expected().outcome() == outcome;
    }

    private static void requireIdentifier(String field, String value, List<String> violations) {
        if (value == null || !IDENTIFIER.matcher(value).matches()) {
            violations.add(field + " must be lower-case letters, digits and hyphens");
        }
    }

    private static void requireText(String field, String value, List<String> violations) {
        if (isBlank(value)) {
            violations.add(field + " is required");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
