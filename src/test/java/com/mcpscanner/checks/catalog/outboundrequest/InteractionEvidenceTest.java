package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.collaborator.FakeCollaborator;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class InteractionEvidenceTest {

    private static final ProbeUserInfo NO_USER_INFO = ProbeUserInfo.of("http://a.oob.test");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsAnHttpRequestWhenAnyInteractionIsHttp() {
        InteractionEvidence evidence = new InteractionEvidence(List.of(dns(), http(Map.of())));

        assertThat(evidence.strength()).isEqualTo(InteractionStrength.HTTP_REQUEST);
    }

    @Test
    void reportsALookupOnlyWhenEveryInteractionIsDns() {
        assertThat(new InteractionEvidence(List.of(dns(), dns())).strength())
                .isEqualTo(InteractionStrength.DNS_LOOKUP_ONLY);
    }

    @Test
    void namesCredentialHeadersCarriedByTheOutboundRequest() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer server-token");
        headers.put("Private-Token", "glpat-x");
        headers.put("X-Api-Key", "k");
        headers.put("Cookie", "sid=1");
        headers.put("Accept", "*/*");
        headers.put("X-Empty-Token", "");

        InteractionEvidence evidence = new InteractionEvidence(List.of(http(headers)));

        assertThat(evidence.forwardedCredentialHeaders(NO_USER_INFO))
                .containsExactly("Authorization", "Private-Token", "X-Api-Key", "Cookie");
    }

    @Test
    void findsNoCredentialsInLookups() {
        assertThat(new InteractionEvidence(List.of(dns())).forwardedCredentialHeaders(NO_USER_INFO)).isEmpty();
    }

    @Test
    void leavesOutTheBasicAuthorizationTheProbesOwnUserInfoProduced() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Basic ZXhhbXBsZS5jb206");
        headers.put("X-Api-Key", "k");

        InteractionEvidence evidence = new InteractionEvidence(List.of(http(headers)));

        assertThat(evidence.forwardedCredentialHeaders(ProbeUserInfo.of("https://example.com@a.oob.test/")))
                .containsExactly("X-Api-Key");
    }

    private static Interaction dns() {
        return FakeCollaborator.interaction("a", InteractionType.DNS, null);
    }

    private static Interaction http(Map<String, String> headers) {
        HttpRequestResponse fetch = HttpRequestResponse.httpRequestResponse(
                OutboundFixtures.post("http://a." + FakeCollaborator.DOMAIN + "/", headers, ""), null);
        return FakeCollaborator.interaction("a", InteractionType.HTTP, fetch);
    }
}
