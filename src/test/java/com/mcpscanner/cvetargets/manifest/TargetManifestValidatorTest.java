package com.mcpscanner.cvetargets.manifest;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class TargetManifestValidatorTest {

    private final TargetManifestValidator validator = new TargetManifestValidator();

    @TempDir
    Path root;

    @Test
    void acceptsACompleteManifest() {
        assertThat(validator.violations(target(valid()))).isEmpty();
    }

    @Test
    void requiresAdvisoryProvenanceForANonBenignTarget() {
        TargetManifest manifest = valid();
        TargetManifest withoutAdvisories = copy(manifest, List.of("not-an-id"), manifest.benign(), manifest.auth(), manifest.arms());

        assertThat(validator.violations(target(withoutAdvisories)))
                .contains("advisory not-an-id is not a CVE or GHSA id");
    }

    @Test
    void acceptsGhsaIdentifiers() {
        TargetManifest manifest = valid();
        TargetManifest ghsa = copy(manifest, List.of("GHSA-2345-6789-cfgh"), false, manifest.auth(), manifest.arms());

        assertThat(validator.violations(target(ghsa))).isEmpty();
    }

    @Test
    void requiresBenignTargetsToExpectSilenceOnBenignArms() {
        TargetManifest manifest = valid();
        TargetManifest benign = copy(manifest, List.of(), true, manifest.auth(), manifest.arms());

        assertThat(validator.violations(target(benign)))
                .contains("arm vulnerable: a benign target's arms must be benign and silent, filtered by minimumSeverity at most",
                        "arm fixed: a benign target's arms must be benign and silent, filtered by minimumSeverity at most");
    }

    @Test
    void acceptsABenignArmSilentFromASeverityFloor() {
        TargetManifest manifest = valid();
        TargetArm silentFromLow = benignArm(new ExpectedOutcome(Outcome.SILENT, null, null, null, AuditIssueSeverity.LOW, null));

        assertThat(validator.violations(target(copy(manifest, List.of(), true, manifest.auth(), List.of(silentFromLow)))))
                .isEmpty();
    }

    @Test
    void acceptsABenignArmThatDeclaresAnIssueItAlsoReports() {
        TargetManifest manifest = valid();
        TargetArm declared = benignArm(ExpectedOutcome.of(Outcome.SILENT).alsoReporting(List.of("Open registration")));

        assertThat(validator.violations(target(copy(manifest, List.of(), true, manifest.auth(), List.of(declared)))))
                .isEmpty();
    }

    @Test
    void refusesADeclaredIssueThatIsBlankOrTheArmsOwnIssueName() {
        TargetManifest manifest = valid();
        TargetArm blank = arm(ManifestTransport.STREAMABLE_HTTP, "/mcp",
                ExpectedOutcome.of(Outcome.FIRE).alsoReporting(List.of(" ")));
        TargetArm ownName = arm(ManifestTransport.STREAMABLE_HTTP, "/mcp",
                new ExpectedOutcome(Outcome.FIRE, "Open registration", null, null, null, null)
                        .alsoReporting(List.of("Open registration")));

        assertThat(validator.violations(target(copy(manifest, manifest.advisories(), false, manifest.auth(),
                List.of(blank))))).containsExactly("arm vulnerable: alsoReports names must not be blank");
        assertThat(validator.violations(target(copy(manifest, manifest.advisories(), false, manifest.auth(),
                List.of(ownName))))).containsExactly(
                "arm vulnerable: alsoReports must not repeat expected.issueName Open registration");
    }

    @Test
    void refusesABenignArmScopedToOneIssueNameOrExactSeverity() {
        TargetManifest manifest = valid();
        TargetArm exactSeverity = benignArm(new ExpectedOutcome(Outcome.SILENT, null, AuditIssueSeverity.MEDIUM, null, null, null));

        assertThat(validator.violations(target(copy(manifest, List.of(), true, manifest.auth(), List.of(exactSeverity)))))
                .containsExactly("arm benign: a benign target's arms must be benign and silent, filtered by minimumSeverity at most");
    }

    @Test
    void requiresARankedSeverityFloorThatDoesNotDuplicateAnExactSeverity() {
        TargetManifest manifest = valid();
        TargetArm falsePositiveFloor = arm(ManifestTransport.STREAMABLE_HTTP, "/mcp",
                new ExpectedOutcome(Outcome.FIRE, null, null, null, AuditIssueSeverity.FALSE_POSITIVE, null));
        TargetArm bothSeverities = arm(ManifestTransport.STREAMABLE_HTTP, "/mcp",
                new ExpectedOutcome(Outcome.FIRE, null, AuditIssueSeverity.HIGH, null, AuditIssueSeverity.LOW, null));

        assertThat(validator.violations(target(copy(manifest, manifest.advisories(), false, manifest.auth(),
                List.of(falsePositiveFloor))))).containsExactly(
                "arm vulnerable: minimumSeverity must be INFORMATION, LOW, MEDIUM or HIGH");
        assertThat(validator.violations(target(copy(manifest, manifest.advisories(), false, manifest.auth(),
                List.of(bothSeverities))))).containsExactly(
                "arm vulnerable: give severity or minimumSeverity, not both");
    }

    private static TargetArm benignArm(ExpectedOutcome expected) {
        return new TargetArm("benign", ArmRole.BENIGN, "1", "pin", "svc", new EndpointSpec(8000, "/mcp"),
                ManifestTransport.STREAMABLE_HTTP, expected);
    }

    @Test
    void requiresATokenAndInstructionsForCredentialedTargets() {
        TargetManifest manifest = valid();
        TargetManifest bearer = copy(manifest, manifest.advisories(), false,
                new AuthSetup(AuthScheme.BEARER, null, null), manifest.arms());

        assertThat(validator.violations(target(bearer)))
                .contains("auth.token is required for scheme BEARER", "auth.obtain must say how the credential is obtained");
    }

    @Test
    void headerSchemeNeedsAHeaderName() {
        TargetManifest manifest = valid();
        TargetManifest header = copy(manifest, manifest.advisories(), false,
                new AuthSetup(AuthScheme.HEADER, "given", new StaticToken("key")), manifest.arms());

        assertThat(validator.violations(target(header))).contains("auth.header is required for scheme HEADER");
    }

    @Test
    void aHeaderNameNeedsTheHeaderScheme() {
        TargetManifest manifest = valid();
        TargetManifest bearer = copy(manifest, manifest.advisories(), false,
                new AuthSetup(AuthScheme.BEARER, "given", new StaticToken("key"), "x-api-key"), manifest.arms());

        assertThat(validator.violations(target(bearer))).contains("auth.header applies only to scheme HEADER");
    }

    @Test
    void rejectsAuthorizationAndMalformedExtraHeaders() {
        TargetManifest manifest = valid();
        TargetManifest headers = copy(manifest, manifest.advisories(), false, new AuthSetup(AuthScheme.NONE, null,
                null, java.util.Map.of("authorization", "x", "Bad Name", "v", "X-Split", "a\r\nb")), manifest.arms());

        assertThat(validator.violations(target(headers))).contains(
                "auth.headers must not set Authorization; use a token scheme",
                "auth.headers has an invalid header: Bad Name",
                "auth.headers has an invalid header: X-Split");
    }

    @Test
    void validatesArmHeaders() {
        TargetManifest manifest = valid();
        TargetArm arm = manifest.arms().get(0);
        TargetArm withHeaders = new TargetArm(arm.name(), arm.role(), arm.version(), arm.pin(), arm.service(),
                arm.endpoint(), arm.transport(), arm.expected(), java.util.Map.of("Authorization", "x"));
        TargetManifest headed = copy(manifest, manifest.advisories(), false, manifest.auth(),
                List.of(withHeaders, manifest.arms().get(1)));

        assertThat(validator.violations(target(headed)))
                .contains("arm " + arm.name() + ": headers must not set Authorization; use a token scheme");
    }

    @Test
    void acceptsWellFormedExtraHeaders() {
        TargetManifest manifest = valid();
        TargetManifest headers = copy(manifest, manifest.advisories(), false, new AuthSetup(AuthScheme.NONE, null,
                null, java.util.Map.of("X-Upstream-Url", "http://upstream.test:3000")), manifest.arms());

        assertThat(validator.violations(target(headers))).isEmpty();
    }

    @Test
    void validatesTokenSourceFields() {
        TargetManifest manifest = valid();
        TargetManifest jwt = copy(manifest, manifest.advisories(), false,
                new AuthSetup(AuthScheme.BEARER, "minted", new Hs256JwtToken(" ", null, 0)), manifest.arms());

        assertThat(validator.violations(target(jwt)))
                .contains("auth.token.secret is required", "auth.token.ttlSeconds must be positive");
    }

    @Test
    void keepsTheComposeFileInsideTheTargetDirectory() {
        TargetManifest manifest = valid();
        TargetManifest escaping = new TargetManifest(manifest.schemaVersion(), manifest.id(), manifest.check(),
                manifest.product(), manifest.advisories(), manifest.source(), false, "../../compose.yaml",
                manifest.auth(), manifest.readiness(), null, null, null, null, manifest.seeds(), manifest.identities(), manifest.arms(), manifest.notes(),
                manifest.smoke(), manifest.checkAccess());

        assertThat(validator.violations(target(escaping))).contains("compose file must live inside the target directory");
    }

    @Test
    void defaultsTheReadTimeoutAndRejectsANonPositiveOne() {
        TargetManifest manifest = valid();
        TargetManifest zero = withReadTimeout(manifest, 0);

        assertThat(manifest.readTimeout()).isEqualTo(java.time.Duration.ofSeconds(10));
        assertThat(withReadTimeout(manifest, 60).readTimeout()).isEqualTo(java.time.Duration.ofSeconds(60));
        assertThat(validator.violations(target(zero))).contains("readTimeoutSeconds must be above 0");
    }

    @Test
    void defaultsTheArmTimeoutToTwentyMinutesAndRejectsANonPositiveOne() {
        TargetManifest manifest = valid();

        assertThat(manifest.armTimeout()).isEqualTo(java.time.Duration.ofMinutes(20));
        assertThat(withArmTimeout(manifest, 3600).armTimeout()).isEqualTo(java.time.Duration.ofHours(1));
        assertThat(validator.violations(target(withArmTimeout(manifest, 0))))
                .contains("armTimeoutSeconds must be above 0");
    }

    @Test
    void rejectsMissingExpectationsAndAnSseArmWithoutSseReadiness() {
        TargetManifest manifest = valid();
        TargetArm sse = arm(ManifestTransport.SSE, "sse", null);
        TargetManifest broken = copy(manifest, manifest.advisories(), false, manifest.auth(), List.of(sse));

        assertThat(validator.violations(target(broken))).contains(
                "arm vulnerable: endpoint.path must start with /",
                "arm vulnerable: transport SSE needs readiness probe SSE_ENDPOINT",
                "arm vulnerable: expected.outcome is required");
    }

    @Test
    void acceptsAnSseArmWithSseReadinessAndRejectsAStreamableArmBesideIt() {
        TargetManifest manifest = valid();
        TargetArm sse = arm(ManifestTransport.SSE, "/sse", ExpectedOutcome.of(Outcome.FIRE));
        TargetManifest sseOnly = withReadiness(copy(manifest, manifest.advisories(), false, manifest.auth(), List.of(sse)),
                new ReadinessSpec(ReadinessProbeType.SSE_ENDPOINT, 30, null));
        TargetManifest mixed = withReadiness(manifest, new ReadinessSpec(ReadinessProbeType.SSE_ENDPOINT, 30, null));

        assertThat(validator.violations(target(sseOnly))).isEmpty();
        assertThat(validator.violations(target(mixed)))
                .contains("arm fixed: transport STREAMABLE_HTTP needs readiness probe MCP_INITIALIZE");
    }

    @Test
    void acceptsAReadinessCallOnlyOnStreamableHttpWithAMethod() {
        TargetManifest manifest = valid();
        SeedRequest call = new SeedRequest("tools/call", null);
        TargetArm sse = arm(ManifestTransport.SSE, "/sse", ExpectedOutcome.of(Outcome.FIRE));
        TargetManifest sseOnly = copy(manifest, manifest.advisories(), false, manifest.auth(), List.of(sse));

        assertThat(validator.violations(target(withReadiness(manifest,
                new ReadinessSpec(ReadinessProbeType.MCP_INITIALIZE, 30, call))))).isEmpty();
        assertThat(validator.violations(target(withReadiness(manifest,
                new ReadinessSpec(ReadinessProbeType.MCP_INITIALIZE, 30, new SeedRequest(" ", null))))))
                .contains("readiness.call.method is required");
        assertThat(validator.violations(target(withReadiness(sseOnly,
                new ReadinessSpec(ReadinessProbeType.SSE_ENDPOINT, 30, call)))))
                .contains("readiness.call needs readiness probe MCP_INITIALIZE");
    }

    @Test
    void acceptsAKnownFlakyArmOnlyWhenItExpectsFireAndGivesAReason() {
        TargetManifest manifest = valid();
        TargetArm flaky = arm(ManifestTransport.STREAMABLE_HTTP, "/mcp",
                new ExpectedOutcome(Outcome.FIRE, null, null, null, null, null, "drops connections"));
        TargetArm silentFlaky = arm(ManifestTransport.STREAMABLE_HTTP, "/mcp",
                new ExpectedOutcome(Outcome.SILENT, null, null, null, null, null, " "));

        assertThat(validator.violations(target(copy(manifest, manifest.advisories(), false, manifest.auth(),
                List.of(flaky))))).isEmpty();
        assertThat(validator.violations(target(copy(manifest, manifest.advisories(), false, manifest.auth(),
                List.of(silentFlaky))))).contains(
                "arm vulnerable: knownFlaky must give the reason",
                "arm vulnerable: knownFlaky applies only to a fire arm");
    }

    @Test
    void acceptsAKnownMissOnlyOnASilentNonBenignArmWithAReason() {
        TargetManifest manifest = valid();
        TargetArm knownMiss = arm(ManifestTransport.STREAMABLE_HTTP, "/mcp",
                new ExpectedOutcome(Outcome.SILENT, null, null, null, null, "the check skips this transport"));
        TargetArm firingMiss = arm(ManifestTransport.STREAMABLE_HTTP, "/mcp",
                new ExpectedOutcome(Outcome.FIRE, null, null, null, null, " "));

        assertThat(validator.violations(target(copy(manifest, manifest.advisories(), false, manifest.auth(),
                List.of(knownMiss))))).isEmpty();
        assertThat(validator.violations(target(copy(manifest, manifest.advisories(), false, manifest.auth(),
                List.of(firingMiss))))).contains(
                "arm vulnerable: knownMiss must give the reason",
                "arm vulnerable: knownMiss applies only to a silent vulnerable or fixed arm");
    }

    @Test
    void acceptsDownloadsWithAPlainFileNameAnHttpsUrlAndSha512Integrity() {
        TargetManifest manifest = withDownloads(valid(), List.of(download("package.tgz")));

        assertThat(validator.violations(target(manifest))).isEmpty();
    }

    @Test
    void defaultsDownloadsToNone() {
        assertThat(valid().downloads()).isEmpty();
    }

    @Test
    void rejectsADownloadFileNameThatIsNotAPlainFileName() {
        List<String> names = List.of("dir/package.tgz", "dir\\package.tgz", ".", "..", " ");

        names.forEach(name -> assertThat(validator.violations(target(withDownloads(valid(),
                List.of(download(name)))))).contains("download " + name + ": file must be a plain file name"));
    }

    @Test
    void rejectsADownloadUrlThatIsNotAbsoluteHttps() {
        List<String> urls = List.of("http://registry.example.test/package.tgz", "/package.tgz", "not a url", "");

        urls.forEach(url -> assertThat(validator.violations(target(withDownloads(valid(),
                List.of(new Download("package.tgz", url, VALID_INTEGRITY))))))
                .contains("download package.tgz: url must be an absolute https URL"));
    }

    @Test
    void rejectsIntegrityThatIsNotSha512OfSixtyFourBytes() {
        String sha256 = "sha256-" + java.util.Base64.getEncoder().encodeToString(new byte[32]);
        String shortSha512 = "sha512-" + java.util.Base64.getEncoder().encodeToString(new byte[32]);
        List<String> integrities = List.of(sha256, shortSha512, "sha512-not*base64", "");

        integrities.forEach(integrity -> assertThat(validator.violations(target(withDownloads(valid(),
                List.of(new Download("package.tgz", "https://registry.example.test/package.tgz", integrity))))))
                .contains("download package.tgz: integrity must be sha512- followed by the base64 of 64 bytes"));
    }

    @Test
    void rejectsADuplicatedDownloadFileName() {
        TargetManifest manifest = withDownloads(valid(), List.of(download("package.tgz"), download("package.tgz")));

        assertThat(validator.violations(target(manifest))).contains("download file package.tgz is duplicated");
    }

    @Test
    void loadsDownloadsFromTheManifestFile() {
        ManifestFixtures.writeTarget(root, "check-a", "target-one", ManifestFixtures.VALID_MANIFEST
                .formatted("target-one", "check-a")
                .replace("\"schemaVersion\": 1,", "\"schemaVersion\": 1,\n  \"downloads\": [{\"file\": \"package.tgz\","
                        + " \"url\": \"https://registry.example.test/package.tgz\", \"integrity\": \"" + VALID_INTEGRITY
                        + "\"}],"));

        assertThat(ManifestFixtures.loadOnly(root, "check-a", "target-one").manifest().downloads())
                .containsExactly(download("package.tgz"));
    }

    private static final String VALID_INTEGRITY = "sha512-" + java.util.Base64.getEncoder().encodeToString(new byte[64]);

    private static Download download(String file) {
        return new Download(file, "https://registry.example.test/" + file, VALID_INTEGRITY);
    }

    private static TargetManifest withDownloads(TargetManifest manifest, List<Download> downloads) {
        return new TargetManifest(manifest.schemaVersion(), manifest.id(), manifest.check(), manifest.product(),
                manifest.advisories(), manifest.source(), manifest.benign(), manifest.compose(), manifest.auth(),
                manifest.readiness(), manifest.readTimeoutSeconds(), manifest.armTimeoutSeconds(), manifest.footprintMb(),
                manifest.maxCatalogItems(), manifest.seeds(), manifest.identities(), manifest.arms(), manifest.notes(),
                manifest.smoke(), manifest.checkAccess(), downloads);
    }

    private static TargetArm arm(ManifestTransport transport, String path, ExpectedOutcome expected) {
        return new TargetArm("vulnerable", ArmRole.VULNERABLE, "1", "pin", "svc", new EndpointSpec(8000, path),
                transport, expected);
    }

    private static TargetManifest withReadiness(TargetManifest manifest, ReadinessSpec readiness) {
        return new TargetManifest(manifest.schemaVersion(), manifest.id(), manifest.check(), manifest.product(),
                manifest.advisories(), manifest.source(), manifest.benign(), manifest.compose(), manifest.auth(),
                readiness, manifest.readTimeoutSeconds(), manifest.armTimeoutSeconds(), manifest.footprintMb(), manifest.maxCatalogItems(), manifest.seeds(), manifest.identities(), manifest.arms(),
                manifest.notes(), manifest.smoke(), manifest.checkAccess());
    }

    private static TargetManifest withReadTimeout(TargetManifest manifest, int seconds) {
        return new TargetManifest(manifest.schemaVersion(), manifest.id(), manifest.check(), manifest.product(),
                manifest.advisories(), manifest.source(), manifest.benign(), manifest.compose(), manifest.auth(),
                manifest.readiness(), seconds, manifest.armTimeoutSeconds(), manifest.footprintMb(), manifest.maxCatalogItems(), manifest.seeds(), manifest.identities(), manifest.arms(),
                manifest.notes(), manifest.smoke(), manifest.checkAccess());
    }

    private static TargetManifest withFootprint(TargetManifest manifest, int megabytes) {
        return new TargetManifest(manifest.schemaVersion(), manifest.id(), manifest.check(), manifest.product(),
                manifest.advisories(), manifest.source(), manifest.benign(), manifest.compose(), manifest.auth(),
                manifest.readiness(), manifest.readTimeoutSeconds(), manifest.armTimeoutSeconds(), megabytes,
                manifest.maxCatalogItems(), manifest.seeds(), manifest.identities(), manifest.arms(), manifest.notes(), manifest.smoke(), manifest.checkAccess());
    }

    private static TargetManifest withArmTimeout(TargetManifest manifest, int seconds) {
        return new TargetManifest(manifest.schemaVersion(), manifest.id(), manifest.check(), manifest.product(),
                manifest.advisories(), manifest.source(), manifest.benign(), manifest.compose(), manifest.auth(),
                manifest.readiness(), manifest.readTimeoutSeconds(), seconds, manifest.footprintMb(), manifest.maxCatalogItems(), manifest.seeds(), manifest.identities(), manifest.arms(),
                manifest.notes(), manifest.smoke(), manifest.checkAccess());
    }

    @Test
    void limitsTheScannedCatalogTo100ItemsPerKindByDefaultAndRequiresAPositiveLimit() {
        assertThat(valid().maxCatalogItems()).isEqualTo(100);
        assertThat(valid().catalogLimit()).isEqualTo(new com.mcpscanner.automation.CatalogLimit(100));
        assertThat(validator.violations(target(withCatalogLimit(valid(), 0))))
                .contains("maxCatalogItems must be above 0");
        assertThat(validator.violations(target(withCatalogLimit(valid(), 500)))).isEmpty();
    }

    private static TargetManifest withCatalogLimit(TargetManifest manifest, int items) {
        return new TargetManifest(manifest.schemaVersion(), manifest.id(), manifest.check(), manifest.product(),
                manifest.advisories(), manifest.source(), manifest.benign(), manifest.compose(), manifest.auth(),
                manifest.readiness(), manifest.readTimeoutSeconds(), manifest.armTimeoutSeconds(), manifest.footprintMb(),
                items, manifest.seeds(), manifest.identities(), manifest.arms(), manifest.notes(), manifest.smoke(),
                manifest.checkAccess());
    }

    @Test
    void requiresAPositiveFootprintAndDefaultsIt() {
        assertThat(valid().footprintMb()).isEqualTo(TargetManifest.DEFAULT_FOOTPRINT_MB);
        assertThat(validator.violations(target(withFootprint(valid(), 0)))).contains("footprintMb must be above 0");
        assertThat(validator.violations(target(withFootprint(valid(), 1536)))).isEmpty();
    }

    private LoadedTarget target(TargetManifest manifest) {
        ManifestFixtures.writeValidTarget(root, "check-a", "target-one");
        return new LoadedTarget(root.resolve("check-a/target-one"), manifest);
    }

    private TargetManifest valid() {
        ManifestFixtures.writeValidTarget(root, "check-a", "target-one");
        return ManifestFixtures.loadOnly(root, "check-a", "target-one").manifest();
    }

    private static TargetManifest copy(TargetManifest manifest, List<String> advisories, boolean benign,
                                       AuthSetup auth, List<TargetArm> arms) {
        return new TargetManifest(manifest.schemaVersion(), manifest.id(), manifest.check(), manifest.product(),
                advisories, manifest.source(), benign, manifest.compose(), auth, manifest.readiness(),
                manifest.readTimeoutSeconds(), manifest.armTimeoutSeconds(), manifest.footprintMb(), manifest.maxCatalogItems(), manifest.seeds(), manifest.identities(), arms,
                manifest.notes(), manifest.smoke(), manifest.checkAccess());
    }
}
