package com.mcpscanner.checks.catalog.filetraversal;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class FindingClassifierTest {

    private static final String FILE_TEXT = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"text\":\"%s\"}]}}";
    private static final String PASSWD_JSON = "root:x:0:0:root:/root:/bin/bash";
    private static final String GIT_JSON = "[core]\\nrepositoryformatversion = 0";
    private static final String DENIED = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"isError\":true,\"content\":[{\"text\":\"Access denied\"}]}}";
    private static final String MISSING = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"isError\":true,\"content\":[{\"text\":\"ENOENT\"}]}}";
    private static final String OK = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"text\":\"hello\"}]}}";

    private final FindingClassifier classifier = new FindingClassifier();
    private final List<TraversalAttempt> attempts = new ArrayList<>();
    private final List<ConfirmedRead> reads = new ArrayList<>();

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void classifiesAnEvasionReadAsABypassOnlyWhenEveryLiteralTwinWasRejected() {
        result(payload("p", PayloadTier.TRAVERSAL, TargetFile.PASSWD), DENIED);
        read(payload("p", PayloadTier.EVASION, TargetFile.PASSWD), String.format(FILE_TEXT, PASSWD_JSON));

        assertThat(types()).containsExactly(FindingKind.FILTER_BYPASS);
    }

    @Test
    void classifiesAnEvasionReadAsAFileReadWhenTheLiteralTwinWasNotRejected() {
        result(payload("p", PayloadTier.TRAVERSAL, TargetFile.PASSWD), OK);
        read(payload("p", PayloadTier.EVASION, TargetFile.PASSWD), String.format(FILE_TEXT, PASSWD_JSON));

        assertThat(types()).containsExactly(FindingKind.FILE_READ);
    }

    @Test
    void neverClaimsABypassFromARoutingMiss() {
        result(payload("p", PayloadTier.TRAVERSAL, TargetFile.PASSWD),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");
        read(payload("p", PayloadTier.EVASION, TargetFile.PASSWD), String.format(FILE_TEXT, PASSWD_JSON));

        assertThat(types()).containsExactly(FindingKind.FILE_READ);
    }

    @Test
    void neverCallsAnEvasionABypassWhenAPlainPathAlreadyReadTheSameFile() {
        result(payload("p", PayloadTier.TRAVERSAL, TargetFile.PASSWD), DENIED);
        read(payload("p", PayloadTier.EVASION, TargetFile.PASSWD), String.format(FILE_TEXT, PASSWD_JSON));
        read(payload("abs", PayloadTier.ABSOLUTE, TargetFile.PASSWD), String.format(FILE_TEXT, PASSWD_JSON));

        assertThat(types()).containsExactly(FindingKind.HOST_FILE_READ);
    }

    @Test
    void neverCallsAnEvasionABypassWhenTheLiteralTwinOnlyReportedAMissingFile() {
        result(payload("p", PayloadTier.TRAVERSAL, TargetFile.PASSWD), MISSING);
        read(payload("p", PayloadTier.EVASION, TargetFile.PASSWD), String.format(FILE_TEXT, PASSWD_JSON));

        assertThat(types()).containsExactly(FindingKind.FILE_READ);
    }

    @Test
    void classifiesGitConfigReads() {
        result(payload("g", PayloadTier.IN_ROOT, TargetFile.GIT_CONFIG), DENIED);
        read(payload("g", PayloadTier.CASE_VARIANT, TargetFile.GIT_CONFIG), String.format(FILE_TEXT, GIT_JSON));
        read(payload("parent", PayloadTier.TRAVERSAL, TargetFile.GIT_CONFIG), String.format(FILE_TEXT, GIT_JSON));

        assertThat(types()).containsExactly(FindingKind.RESTRICTED_PATH_BYPASS, FindingKind.REPOSITORY_METADATA_READ);
        assertThat(classifier.classify(new ContentTrial(attempts, reads)))
                .extracting(finding -> finding.evidence().size()).containsExactly(3, 2);
    }

    @Test
    void dropsAPartialDisclosureWhenTheFullFileWasRead() {
        read(payload("a", PayloadTier.ABSOLUTE, TargetFile.PASSWD), String.format(FILE_TEXT, "\\\"root:x:0:0\\\" bad"));
        read(payload("b", PayloadTier.ABSOLUTE, TargetFile.PASSWD), String.format(FILE_TEXT, PASSWD_JSON));

        assertThat(types()).containsExactly(FindingKind.HOST_FILE_READ);
    }

    @Test
    void reportsAnArbitraryHostFileReadInsteadOfTraversalWhenAnAbsolutePathAlsoReads() {
        read(payload("a", PayloadTier.ABSOLUTE, TargetFile.PASSWD), String.format(FILE_TEXT, PASSWD_JSON));
        read(payload("t", PayloadTier.TRAVERSAL, TargetFile.PASSWD), String.format(FILE_TEXT, PASSWD_JSON));

        assertThat(types()).containsExactly(FindingKind.HOST_FILE_READ);
    }

    @Test
    void keepsAtMostThreeReadsAsEvidenceForOneFinding() {
        for (int i = 0; i < 5; i++) {
            read(payload("a" + i, PayloadTier.ABSOLUTE, TargetFile.PASSWD), String.format(FILE_TEXT, PASSWD_JSON));
        }

        Finding finding = classifier.classify(new ContentTrial(attempts, reads)).get(0);
        assertThat(finding.observations()).hasSize(4);
        assertThat(finding.evidence()).hasSize(2);
    }

    @Test
    void attachesTheCandidateAndItsMissingFileTwinButNotTheMissingDirectoryTwin() {
        ConfirmedRead read = read(payload("a", PayloadTier.ABSOLUTE, TargetFile.PASSWD),
                String.format(FILE_TEXT, PASSWD_JSON));

        Finding finding = classifier.classify(new ContentTrial(attempts, reads)).get(0);

        assertThat(finding.evidence()).containsExactly(read.candidate().exchange(), read.controls().get(0).exchange());
        assertThat(finding.observations()).containsExactly(
                "a/ABSOLUTE/passwd returned the Unix password file; the matched missing paths "
                        + read.controls().get(0).sentValue() + " and " + read.controls().get(1).sentValue()
                        + " did not.",
                "Attached requests, in order: a/ABSOLUTE/passwd, " + read.controls().get(0).sentValue() + ".");
    }

    @Test
    void attachesTheRejectedLiteralBeforeTheCandidateOfABypass() {
        TraversalAttempt literal = result(payload("p", PayloadTier.TRAVERSAL, TargetFile.PASSWD), DENIED);
        ConfirmedRead read = read(payload("p", PayloadTier.EVASION, TargetFile.PASSWD),
                String.format(FILE_TEXT, PASSWD_JSON));

        Finding finding = classifier.classify(new ContentTrial(attempts, reads)).get(0);

        assertThat(finding.evidence()).containsExactly(literal.exchange(), read.candidate().exchange(),
                read.controls().get(0).exchange());
        assertThat(finding.observations()).last().isEqualTo("Attached requests, in order: p/TRAVERSAL/passwd, "
                + "p/EVASION/passwd, " + read.controls().get(0).sentValue() + ".");
    }

    @Test
    void attachesOnlyTheFirstPartialReadAndNamesTheOthersInText() {
        String partial = String.format(FILE_TEXT, "\\\"root:x:0:0\\\" bad");
        ConfirmedRead first = read(payload("a", PayloadTier.TRAVERSAL, TargetFile.PASSWD), partial);
        read(payload("b", PayloadTier.TRAVERSAL, TargetFile.PASSWD), partial);

        Finding finding = classifier.classify(new ContentTrial(attempts, reads)).get(0);

        assertThat(finding.kind()).isEqualTo(FindingKind.PARTIAL_FILE_DISCLOSURE);
        assertThat(finding.evidence()).containsExactly(first.candidate().exchange(), first.controls().get(0).exchange());
        assertThat(finding.observations()).hasSize(3);
        assertThat(finding.observations().get(1)).startsWith("b/TRAVERSAL/passwd returned the opening bytes");
    }

    @Test
    void namesTheRejectedLiteralInTheMeaningOfABypass() {
        result(new TraversalPayload("g", TargetFile.GIT_CONFIG, PayloadTier.TRAVERSAL, "docs/../.git/config"), DENIED);
        read(new TraversalPayload("g", TargetFile.GIT_CONFIG, PayloadTier.CASE_VARIANT, "docs/../.gIt/config"),
                String.format(FILE_TEXT, GIT_JSON));

        Finding finding = classifier.classify(new ContentTrial(attempts, reads)).get(0);
        assertThat(finding.kind()).isEqualTo(FindingKind.RESTRICTED_PATH_BYPASS);
        assertThat(finding.meaning()).startsWith("The field rejected docs/../.git/config but returned");
    }

    private List<FindingKind> types() {
        return classifier.classify(new ContentTrial(attempts, reads)).stream().map(Finding::kind).toList();
    }

    private static TraversalPayload payload(String family, PayloadTier tier, TargetFile file) {
        return new TraversalPayload(family, file, tier, family + "/" + tier + "/" + file.fileName());
    }

    private TraversalAttempt result(TraversalPayload payload, String body) {
        TraversalAttempt result = new TraversalAttempt(payload, payload.value(), mock(HttpRequestResponse.class),
                TraversalReplyTest.reply(body));
        attempts.add(result);
        return result;
    }

    private ConfirmedRead read(TraversalPayload payload, String body) {
        TraversalAttempt candidate = result(payload, body);
        ConfirmedRead read = new ConfirmedRead(candidate, List.of(missing(payload, payload.missingFileTwin("m")),
                missing(payload, payload.missingDirectoryTwin("m"))));
        reads.add(read);
        return read;
    }

    private static TraversalAttempt missing(TraversalPayload payload, String value) {
        return new TraversalAttempt(payload, value, mock(HttpRequestResponse.class), TraversalReplyTest.reply(MISSING));
    }
}
