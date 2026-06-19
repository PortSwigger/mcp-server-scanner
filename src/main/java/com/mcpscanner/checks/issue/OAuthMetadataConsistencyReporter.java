package com.mcpscanner.checks.issue;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.oauth.OAuthMetadataConsistencyListener;
import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Surfaces all OAuth metadata consistency findings as INFORMATIONAL Burp audit issues
 * attached directly to the site map. Three categories are handled:
 * <ul>
 *   <li>RFC 8414 §3.3 issuer mismatch in the AS metadata document.</li>
 *   <li>PRM document's {@code authorization_servers[0]} on a different host than the MCP endpoint.</li>
 *   <li>AS metadata endpoint (e.g. {@code authorization_endpoint}) on a different host than the AS issuer.</li>
 * </ul>
 * The connect flow is never interrupted; each finding is purely informational.
 */
public final class OAuthMetadataConsistencyReporter implements OAuthMetadataConsistencyListener {

    private static final String ISSUE_NAME_ISSUER_MISMATCH =
            "OAuth authorization server metadata violates RFC 8414 §3.3 (issuer mismatch)";
    private static final String ISSUE_NAME_PRM_CROSS_DOMAIN =
            "OAuth PRM references cross-domain authorization server";
    private static final String ISSUE_NAME_AS_ENDPOINT_CROSS_DOMAIN =
            "OAuth AS metadata %s points to a different domain than the AS issuer";

    private static final String RFC_8414_QUOTE =
            "The issuer value returned MUST be identical to the authorization server's issuer "
                    + "identifier value into which the well-known URI string was inserted to "
                    + "create the URL used to retrieve the metadata.";

    private static final String RFC_8414_REF = "https://datatracker.ietf.org/doc/html/rfc8414";
    private static final String RFC_8414_3_3_REF = RFC_8414_REF + "#section-3.3";
    private static final String RFC_9728_REF = "https://datatracker.ietf.org/doc/html/rfc9728";

    private static final Cwe CWE_DATA_AUTHENTICITY =
            new Cwe(345, "Insufficient Verification of Data Authenticity");
    private static final Cwe CWE_ORIGIN_VALIDATION =
            new Cwe(346, "Origin Validation Error");

    private static final String ISSUER_MISMATCH_BACKGROUND =
            "OAuth 2.0 authorization-server metadata is trusted to bootstrap the entire auth flow, "
                    + "so RFC 8414 §3.3 requires the 'issuer' it declares to be byte-identical to the "
                    + "URL the document was fetched from. A mismatch means the metadata cannot be tied "
                    + "back to the host that served it, which is the foundation for issuer-substitution "
                    + "and metadata-spoofing attacks against clients that key trust decisions on the "
                    + "issuer.";
    private static final String PRM_CROSS_DOMAIN_BACKGROUND =
            "An MCP resource publishes Protected Resource Metadata (RFC 9728) naming the authorization "
                    + "server clients must use. When that server sits on an unrelated domain, the "
                    + "resource is delegating authentication to an origin a client cannot verify is "
                    + "operator-controlled, expanding the trust boundary and enabling token requests "
                    + "to be steered to an attacker-influenced authorization server.";
    private static final String AS_ENDPOINT_CROSS_DOMAIN_BACKGROUND =
            "Endpoints declared in OAuth authorization-server metadata (RFC 8414) are expected to be "
                    + "co-hosted with the issuer. An endpoint on a different domain means part of the "
                    + "OAuth exchange — authorization, token, or registration — is routed to an origin "
                    + "outside the issuer's control, which can redirect credentials and authorization "
                    + "codes to an unverified host.";

    private final MontoyaApi api;
    private final McpEventLog eventLog;

    public OAuthMetadataConsistencyReporter(MontoyaApi api, McpEventLog eventLog) {
        this.api = api;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
    }

    @Override
    public void onIssuerMismatch(URI metadataUrl,
                                 String expectedIssuer,
                                 String returnedIssuer,
                                 byte[] rawResponseBody) {
        emitIssue(() -> buildIssuerMismatchIssue(metadataUrl, expectedIssuer, returnedIssuer, rawResponseBody),
                "RFC 8414 §3.3 issuer-mismatch");
    }

    @Override
    public void onPrmAuthorizationServerHostMismatch(URI prmDocUrl,
                                                      String mcpEndpointHost,
                                                      String authorizationServerUrl,
                                                      byte[] rawPrmBody) {
        emitIssue(() -> buildPrmCrossDomainIssue(prmDocUrl, mcpEndpointHost, authorizationServerUrl, rawPrmBody),
                "PRM cross-domain authorization server");
    }

    @Override
    public void onAsEndpointHostMismatch(URI metadataUrl,
                                          String asIssuer,
                                          String endpointName,
                                          String endpointUrl,
                                          byte[] rawAsBody) {
        emitIssue(() -> buildAsEndpointMismatchIssue(metadataUrl, asIssuer, endpointName, endpointUrl, rawAsBody),
                "AS endpoint host mismatch (" + endpointName + ")");
    }

    private void emitIssue(java.util.function.Supplier<AuditIssue> issueSupplier, String context) {
        try {
            api.siteMap().add(issueSupplier.get());
        } catch (RuntimeException ex) {
            eventLog.warn("Failed to add OAuth metadata consistency issue (" + context
                    + ") to site map: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
        }
    }

    private static AuditIssue buildIssuerMismatchIssue(URI metadataUrl,
                                                        String expectedIssuer,
                                                        String returnedIssuer,
                                                        byte[] rawResponseBody) {
        HttpRequestResponse evidence = buildEvidence(metadataUrl, rawResponseBody);

        String detail = new IssueBodyBuilder()
                .paragraph("The OAuth 2.0 authorization-server metadata document fetched from "
                        + metadataUrl + " declares an issuer that does not match the URL the "
                        + "document was retrieved from. RFC 8414 §3.3 requires the issuer "
                        + "returned in the metadata document to be byte-identical to the issuer "
                        + "value used to derive the well-known URL.")
                .findings(List.of(
                        "Fetched: " + metadataUrl,
                        "Expected issuer: " + expectedIssuer,
                        "Server-declared issuer: " + returnedIssuer))
                .section("RFC 8414 §3.3", "<p><i>" + RFC_8414_QUOTE + "</i></p>")
                .paragraph("The MCP Server Scanner proceeded by parsing the metadata document "
                        + "leniently so the connect flow could complete; this finding records the "
                        + "non-compliant protocol behaviour so it can be reviewed and fixed by the "
                        + "authorization server operator.")
                .build();

        String remediation = new IssueBodyBuilder()
                .paragraph("Update the authorization server metadata document at " + metadataUrl
                        + " so that its 'issuer' field equals " + wellKnownStripped(metadataUrl)
                        + ". Alternatively, update the protected-resource metadata "
                        + "(authorization_servers) to reference the host that the AS metadata "
                        + "document actually declares as its issuer.")
                .build();

        String background = IssueMetadataRenderer.background(
                ISSUER_MISMATCH_BACKGROUND,
                List.of(CWE_DATA_AUTHENTICITY),
                List.of(RFC_8414_3_3_REF));

        return AuditIssue.auditIssue(
                ISSUE_NAME_ISSUER_MISMATCH,
                detail,
                remediation,
                metadataUrl.toString(),
                AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN,
                background, null, AuditIssueSeverity.INFORMATION,
                List.of(evidence));
    }

    private static AuditIssue buildPrmCrossDomainIssue(URI prmDocUrl,
                                                        String mcpEndpointHost,
                                                        String authorizationServerUrl,
                                                        byte[] rawPrmBody) {
        HttpRequestResponse evidence = buildEvidence(prmDocUrl, rawPrmBody);

        String detail = new IssueBodyBuilder()
                .paragraph("The Protected Resource Metadata (PRM) document at " + prmDocUrl
                        + " declares an authorization server on a different domain than the MCP "
                        + "endpoint that served it. An MCP endpoint at " + mcpEndpointHost
                        + " should not delegate authentication to an unrelated domain without "
                        + "explicit operator intent.")
                .findings(List.of(
                        "PRM document URL: " + prmDocUrl,
                        "MCP endpoint host: " + mcpEndpointHost,
                        "Declared authorization server: " + authorizationServerUrl))
                .paragraph("The MCP Server Scanner accepted this configuration and continued "
                        + "discovery. Review whether the cross-domain authorization server is "
                        + "intentional and ensure the referenced server is under the operator's "
                        + "control.")
                .build();

        String remediation = new IssueBodyBuilder()
                .paragraph("Verify that the authorization server declared in the PRM document "
                        + "at " + prmDocUrl + " is intentional. If the MCP server is expected "
                        + "to use a first-party authorization server, update "
                        + "authorization_servers[0] to point to a server on " + mcpEndpointHost
                        + ". If cross-domain delegation is intentional, document the relationship "
                        + "and ensure the referenced AS is trusted.")
                .build();

        String background = IssueMetadataRenderer.background(
                PRM_CROSS_DOMAIN_BACKGROUND,
                List.of(CWE_DATA_AUTHENTICITY, CWE_ORIGIN_VALIDATION),
                List.of(RFC_9728_REF));

        return AuditIssue.auditIssue(
                ISSUE_NAME_PRM_CROSS_DOMAIN,
                detail,
                remediation,
                prmDocUrl.toString(),
                AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN,
                background, null, AuditIssueSeverity.INFORMATION,
                List.of(evidence));
    }

    private static AuditIssue buildAsEndpointMismatchIssue(URI metadataUrl,
                                                            String asIssuer,
                                                            String endpointName,
                                                            String endpointUrl,
                                                            byte[] rawAsBody) {
        HttpRequestResponse evidence = buildEvidence(metadataUrl, rawAsBody);
        String issueName = String.format(ISSUE_NAME_AS_ENDPOINT_CROSS_DOMAIN, endpointName);

        String detail = new IssueBodyBuilder()
                .paragraph("The OAuth 2.0 authorization-server metadata document at " + metadataUrl
                        + " declares an " + endpointName + " that is hosted on a different domain "
                        + "than the AS issuer. Endpoints in AS metadata should be co-hosted with "
                        + "the issuer to prevent unauthorized redirect of sensitive OAuth exchanges.")
                .findings(List.of(
                        "AS metadata URL: " + metadataUrl,
                        "AS issuer: " + asIssuer,
                        endpointName + ": " + endpointUrl))
                .paragraph("The MCP Server Scanner accepted this configuration and continued. "
                        + "Review whether the cross-domain endpoint is intentional.")
                .build();

        String remediation = new IssueBodyBuilder()
                .paragraph("Ensure that " + endpointName + " declared in the AS metadata at "
                        + metadataUrl + " is hosted on the same domain as the AS issuer "
                        + asIssuer + ". If cross-domain endpoints are intentional (e.g. CDN or "
                        + "federated identity), verify that the endpoint is under the operator's "
                        + "control and document the configuration.")
                .build();

        String background = IssueMetadataRenderer.background(
                AS_ENDPOINT_CROSS_DOMAIN_BACKGROUND,
                List.of(CWE_DATA_AUTHENTICITY, CWE_ORIGIN_VALIDATION),
                List.of(RFC_8414_REF));

        return AuditIssue.auditIssue(
                issueName,
                detail,
                remediation,
                metadataUrl.toString(),
                AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN,
                background, null, AuditIssueSeverity.INFORMATION,
                List.of(evidence));
    }

    private static HttpRequestResponse buildEvidence(URI url, byte[] rawBody) {
        HttpService service = serviceFor(url);
        HttpRequest request = HttpRequest.httpRequestFromUrl(url.toString())
                .withService(service)
                .withMethod("GET");
        String bodyText = rawBody != null && rawBody.length > 0
                ? new String(rawBody, StandardCharsets.UTF_8)
                : "";
        HttpResponse response = HttpResponse.httpResponse(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + bodyText);
        return HttpRequestResponse.httpRequestResponse(request, response);
    }

    private static String wellKnownStripped(URI metadataUrl) {
        String url = metadataUrl.toString();
        int idx = url.indexOf("/.well-known/");
        return idx > 0 ? url.substring(0, idx) : url;
    }

    private static HttpService serviceFor(URI url) {
        boolean secure = "https".equalsIgnoreCase(url.getScheme());
        int port = url.getPort() != -1 ? url.getPort() : (secure ? 443 : 80);
        return HttpService.httpService(url.getHost(), port, secure);
    }
}
