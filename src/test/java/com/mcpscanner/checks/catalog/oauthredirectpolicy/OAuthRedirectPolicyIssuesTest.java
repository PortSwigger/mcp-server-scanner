package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class OAuthRedirectPolicyIssuesTest {

    private static final URI AUTHORIZE = URI.create("https://auth.example.com/authorize");

    private final OAuthRedirectPolicyIssues assembler =
            new OAuthRedirectPolicyIssues(OAuthRedirectPolicyDescriptor.DESCRIPTOR);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    private static RedirectFinding finding(FindingKind kind, String summary, List<HttpRequestResponse> evidence) {
        return new RedirectFinding(kind, AUTHORIZE, summary, evidence);
    }

    private static List<HttpRequestResponse> exchanges(int count) {
        return IntStream.range(0, count).mapToObj(index -> mock(HttpRequestResponse.class)).toList();
    }

    @Test
    void reportsNothingWithoutFindings() {
        assertThat(assembler.issues(List.of())).isEmpty();
    }

    @Test
    void reportsOneIssuePerFindingKind() {
        List<AuditIssue> issues = assembler.issues(List.of(
                finding(FindingKind.CODE_DELIVERY, "a", exchanges(1)),
                finding(FindingKind.ERROR_DELIVERY, "b", exchanges(1)),
                finding(FindingKind.CODE_DELIVERY, "c", exchanges(1))));

        assertThat(issues).extracting(AuditIssue::name).containsExactly(
                FindingKind.CODE_DELIVERY.issueName(), FindingKind.ERROR_DELIVERY.issueName());
    }

    @Test
    void issueCarriesTheTypeRatingAndRemediation() {
        AuditIssue issue = assembler.issues(List.of(finding(FindingKind.WILDCARD_EXPANSION, "a", exchanges(1))))
                .get(0);

        assertThat(issue.severity()).isEqualTo(FindingKind.WILDCARD_EXPANSION.severity());
        assertThat(issue.confidence()).isEqualTo(FindingKind.WILDCARD_EXPANSION.confidence());
        assertThat(issue.remediation()).isEqualTo(FindingKind.WILDCARD_EXPANSION.remediation());
    }

    @Test
    void detailListsEverySummaryBetweenObservationAndLimits() {
        AuditIssue issue = assembler.issues(List.of(
                finding(FindingKind.CODE_DELIVERY, "first summary", exchanges(1)),
                finding(FindingKind.CODE_DELIVERY, "second summary", exchanges(1)))).get(0);

        assertThat(issue.detail()).containsSubsequence("redirected an authorization code", "first summary",
                "second summary", "does not compare redirect_uri exactly");
    }

    @Test
    void backgroundCarriesTheCheckBackground() {
        AuditIssue issue = assembler.issues(List.of(finding(FindingKind.CODE_DELIVERY, "a", exchanges(1)))).get(0);

        assertThat(issue.definition().background()).contains("exact string match");
    }

    @Test
    void evidenceIsDistinctAcrossFindings() {
        List<HttpRequestResponse> shared = exchanges(2);

        AuditIssue issue = assembler.issues(List.of(
                finding(FindingKind.CODE_DELIVERY, "a", shared),
                finding(FindingKind.CODE_DELIVERY, "b", shared))).get(0);

        assertThat(issue.requestResponses()).containsExactlyElementsOf(shared);
    }

    @Test
    void evidenceIsOnlyTheFirstFindingsExchanges() {
        List<HttpRequestResponse> first = exchanges(3);
        List<HttpRequestResponse> second = exchanges(3);

        AuditIssue issue = assembler.issues(List.of(
                finding(FindingKind.CODE_DELIVERY, "a", first),
                finding(FindingKind.CODE_DELIVERY, "b", second))).get(0);

        assertThat(issue.requestResponses()).containsExactlyElementsOf(first);
    }

    @Test
    void detailNamesTheFirstCaseAsTheAttachedOneWhenSeveralCasesWereFound() {
        AuditIssue issue = assembler.issues(List.of(
                finding(FindingKind.CODE_DELIVERY, "first summary", exchanges(3)),
                finding(FindingKind.CODE_DELIVERY, "second summary", exchanges(3)))).get(0);

        assertThat(issue.detail()).containsSubsequence("second summary",
                "The attached exchanges show only the first case listed: first summary.");
    }

    @Test
    void detailNamesNoAttachedCaseForASingleFinding() {
        AuditIssue issue = assembler.issues(List.of(finding(FindingKind.CODE_DELIVERY, "only", exchanges(3)))).get(0);

        assertThat(issue.detail()).doesNotContain("The attached exchanges");
    }
}
