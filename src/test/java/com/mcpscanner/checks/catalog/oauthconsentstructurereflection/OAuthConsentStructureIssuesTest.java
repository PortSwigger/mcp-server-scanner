package com.mcpscanner.checks.catalog.oauthconsentstructurereflection;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.shared.oauth.RegisteredClient;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuthConsentStructureIssuesTest {

    private static final StructureMarker MARKER = StructureMarker.withNonce("abcd");
    private static final String AUTHORIZE_URL = "https://as.example/authorize?state=" + MARKER.token();
    private static final String CONSENT_URL = "https://as.example/consent";
    private static final String CONTROL_URL = "https://as.example/authorize?control";
    private static final String CONSENT_PAGE = "HTTP/1.1 200 OK\r\n\r\n<p " + MARKER.attributeName() + "=\"1\"><"
            + MARKER.elementName() + "></" + MARKER.elementName() + "></p>";

    private HttpRequestResponse registration;
    private HttpRequestResponse authorize;
    private HttpRequestResponse consent;
    private HttpRequestResponse control;

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
        registration = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl("https://as.example/register").withMethod("POST")
                        .withBody("{\"client_name\":\"MCP Scanner " + MARKER.token() + "\"}"),
                HttpResponse.httpResponse("HTTP/1.1 201 Created\r\n\r\n"));
        authorize = HttpRequestResponse.httpRequestResponse(requestWithQuery(AUTHORIZE_URL),
                HttpResponse.httpResponse("HTTP/1.1 302 Found\r\n\r\n"));
        consent = exchange(CONSENT_URL, CONSENT_PAGE);
        control = exchange(CONTROL_URL, "HTTP/1.1 400 Bad Request\r\n\r\n");
    }

    @Test
    void attributeIssueNamesTheAttributeMarkerAndCitesTheControl() {
        AuditIssue issue = singleIssue(StructurePlacement.ATTRIBUTE, ReflectedField.STATE,
                List.of(authorize, consent));

        assertThat(issue.detail()).contains("mcpscan-at-abcd").doesNotContain("(mcpscan-el-abcd)")
                .contains("cid.mcpscan-unregistered-control")
                .contains("No enforced Content-Security-Policy");
        assertThat(issue.remediation()).contains("Encode client metadata");
    }

    @Test
    void stateIssueAttachesThePageTrailAndTheControlButNotTheRegistration() {
        AuditIssue issue = singleIssue(StructurePlacement.ATTRIBUTE, ReflectedField.STATE,
                List.of(authorize, consent));

        assertThat(issue.requestResponses()).extracting(exchange -> exchange.request().url())
                .containsExactly(AUTHORIZE_URL, CONSENT_URL, CONTROL_URL);
        assertThat(requestHighlights(issue.requestResponses().get(0))).containsExactly(MARKER.token());
        assertThat(responseHighlights(issue.requestResponses().get(1))).containsExactly(MARKER.attributeName());
        assertThat(issue.requestResponses().get(2).requestMarkers()).isEmpty();
        assertThat(issue.requestResponses().get(2).responseMarkers()).isEmpty();
    }

    @Test
    void stateIssueOnASingleHopPageHighlightsTheStateAndTheStructureOnTheSameExchange() {
        HttpRequestResponse page = HttpRequestResponse.httpRequestResponse(requestWithQuery(AUTHORIZE_URL),
                HttpResponse.httpResponse(CONSENT_PAGE));

        AuditIssue issue = singleIssue(StructurePlacement.ELEMENT, ReflectedField.STATE, List.of(page));

        assertThat(issue.requestResponses()).extracting(exchange -> exchange.request().url())
                .containsExactly(AUTHORIZE_URL, CONTROL_URL);
        assertThat(requestHighlights(issue.requestResponses().get(0))).containsExactly(MARKER.token());
        assertThat(responseHighlights(issue.requestResponses().get(0)))
                .containsExactly(MARKER.elementName(), MARKER.elementName());
    }

    @Test
    void clientNameIssueAttachesTheRegistrationAndThePageTrailButNotTheControl() {
        AuditIssue issue = singleIssue(StructurePlacement.ELEMENT, ReflectedField.CLIENT_NAME,
                List.of(authorize, consent));

        assertThat(issue.requestResponses()).extracting(exchange -> exchange.request().url())
                .containsExactly("https://as.example/register", AUTHORIZE_URL, CONSENT_URL);
        assertThat(requestHighlights(issue.requestResponses().get(0))).containsExactly(MARKER.token());
        assertThat(issue.requestResponses().get(1).requestMarkers()).isEmpty();
        assertThat(responseHighlights(issue.requestResponses().get(2)))
                .containsExactly(MARKER.elementName(), MARKER.elementName());
    }

    private AuditIssue singleIssue(StructurePlacement placement, ReflectedField field,
                                   List<HttpRequestResponse> trail) {
        ConsentStructureEvidence evidence = new ConsentStructureEvidence(
                new RegisteredClient("cid", List.of(ConsentClientRegistration.REDIRECT_URI.toString()), registration,
                        Optional.empty()),
                new AuthorizationPage(URI.create(CONSENT_URL), trail),
                new AuthorizationPage(URI.create(CONTROL_URL), List.of(control)),
                List.of(new FieldReflection(field, MARKER, placement)),
                ScriptExecutionAssessment.of(List.of()));
        List<AuditIssue> issues = new OAuthConsentStructureIssues(OAuthConsentStructureDescriptor.DESCRIPTOR)
                .issuesFor(evidence);
        assertThat(issues).hasSize(1);
        return issues.get(0);
    }

    private static List<String> requestHighlights(HttpRequestResponse exchange) {
        return marked(exchange.request().toByteArray(), exchange.requestMarkers());
    }

    private static List<String> responseHighlights(HttpRequestResponse exchange) {
        return marked(exchange.response().toByteArray(), exchange.responseMarkers());
    }

    private static List<String> marked(ByteArray message, List<Marker> markers) {
        byte[] bytes = message.getBytes();
        return markers.stream()
                .map(marker -> new String(Arrays.copyOfRange(bytes, marker.range().startIndexInclusive(),
                        marker.range().endIndexExclusive()), StandardCharsets.UTF_8))
                .toList();
    }

    private static HttpRequest requestWithQuery(String url) {
        URI uri = URI.create(url);
        ByteArray wire = ByteArray.byteArray("GET " + uri.getRawPath() + "?" + uri.getRawQuery() + " HTTP/1.1\r\n\r\n");
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn(url);
        when(request.toByteArray()).thenReturn(wire);
        return request;
    }

    private static HttpRequestResponse exchange(String url, String response) {
        return HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequestFromUrl(url),
                HttpResponse.httpResponse(response));
    }
}
