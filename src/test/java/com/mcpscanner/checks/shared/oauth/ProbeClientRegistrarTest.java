package com.mcpscanner.checks.shared.oauth;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.util.List;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.json;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.status;
import static org.assertj.core.api.Assertions.assertThat;

class ClientRegistrarTest {

    private static final URI ENDPOINT = URI.create("https://auth.example.com/register");
    private static final String MANAGED = "https://auth.example.com/register/c1";
    private static final List<String> REDIRECT_URIS = List.of("https://client.example.com/cb");
    private static final ClientMetadata METADATA = new ClientMetadata("MCP Scanner <x>", REDIRECT_URIS,
            List.of("authorization_code", "refresh_token"));
    private static final String ACCEPTED_BODY =
            "{\"client_id\":\"c1\",\"redirect_uris\":[\"https://client.example.com/cb\"]}";

    private ScriptedHttp http;
    private ProbeClientRegistrar registrar;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        http = new ScriptedHttp();
        registrar = new ProbeClientRegistrar(http.oauth(), ENDPOINT);
    }

    private Registration registerAnswering(String rawResponse) {
        http.on("POST", ENDPOINT.toString(), rawResponse);
        return registrar.register(METADATA);
    }

    private static String managed(String uri, String token) {
        return "{\"client_id\":\"c1\",\"redirect_uris\":[\"https://client.example.com/cb\"],"
                + "\"registration_client_uri\":\"" + uri + "\",\"registration_access_token\":\"" + token + "\"}";
    }

    @Test
    void exposesItsEndpoint() {
        assertThat(registrar.endpoint()).isEqualTo(ENDPOINT);
    }

    @Test
    void postsAnonymousPublicClientMetadataAsJson() throws Exception {
        registerAnswering(status(500));

        HttpRequest sent = http.sent().get(0);
        JsonNode body = McpObjectMapper.INSTANCE.readTree(sent.bodyToString());
        assertThat(sent.method()).isEqualTo("POST");
        assertThat(sent.url()).isEqualTo(ENDPOINT.toString());
        assertThat(sent.headerValue("Content-Type")).isEqualTo("application/json");
        assertThat(sent.headerValue("Authorization")).isNull();
        assertThat(body.path("client_name").asText()).isEqualTo("MCP Scanner <x>");
        assertThat(body.path("redirect_uris")).extracting(JsonNode::asText).containsExactlyElementsOf(REDIRECT_URIS);
        assertThat(body.path("token_endpoint_auth_method").asText()).isEqualTo("none");
        assertThat(body.path("response_types")).extracting(JsonNode::asText).containsExactly("code");
        assertThat(body.path("grant_types")).extracting(JsonNode::asText)
                .containsExactly("authorization_code", "refresh_token");
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 201})
    void successWithClientIdAndRedirectUrisIsAccepted(int status) {
        Registration registration = registerAnswering(json(status, ACCEPTED_BODY));

        assertThat(registration.status()).isEqualTo(RegistrationStatus.ACCEPTED);
        assertThat(registration.client()).hasValueSatisfying(client -> {
            assertThat(client.clientId()).isEqualTo("c1");
            assertThat(client.redirectUris()).containsExactlyElementsOf(REDIRECT_URIS);
            assertThat(client.evidence().request().url()).isEqualTo(ENDPOINT.toString());
            assertThat(client.management()).isEmpty();
        });
        assertThat(registration.exchange()).isPresent();
    }

    @Test
    void successWithEmptyRedirectUrisArrayIsAccepted() {
        Registration registration = registerAnswering(json(201, "{\"client_id\":\"c1\",\"redirect_uris\":[]}"));

        assertThat(registration.status()).isEqualTo(RegistrationStatus.ACCEPTED);
        assertThat(registration.client()).hasValueSatisfying(client -> assertThat(client.redirectUris()).isEmpty());
    }

    @Test
    void successThatDoesNotEchoTheRedirectUrisIsAcceptedButListsNone() {
        Registration registration = registerAnswering(json(201, "{\"client_id\":\"c1\"}"));

        assertThat(registration.status()).isEqualTo(RegistrationStatus.ACCEPTED);
        assertThat(registration.clientListingAll(REDIRECT_URIS)).isEmpty();
    }

    @Test
    void successWithNonArrayRedirectUrisListsNone() {
        Registration registration = registerAnswering(json(201,
                "{\"client_id\":\"c1\",\"redirect_uris\":\"https://client.example.com/cb\"}"));

        assertThat(registration.clientListingAll(REDIRECT_URIS)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 422})
    void explicitRejectionStatusIsRejected(int status) {
        Registration registration = registerAnswering(json(status, "{\"error\":\"invalid_redirect_uri\"}"));

        assertThat(registration.status()).isEqualTo(RegistrationStatus.REJECTED);
        assertThat(registration.client()).isEmpty();
        assertThat(registration.exchange()).isPresent();
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 403, 404, 500, 503})
    void otherFailureStatusIsInconclusive(int status) {
        Registration registration = registerAnswering(json(status, ACCEPTED_BODY));

        assertThat(registration.status()).isEqualTo(RegistrationStatus.INCONCLUSIVE);
        assertThat(registration.client()).isEmpty();
        assertThat(registration.exchange()).isPresent();
    }

    @Test
    void tooManyRequestsIsInconclusiveWithoutExchange() {
        Registration registration = registerAnswering(status(429));

        assertThat(registration.status()).isEqualTo(RegistrationStatus.INCONCLUSIVE);
        assertThat(registration.exchange()).isEmpty();
    }

    @Test
    void noResponseIsInconclusiveWithoutExchange() {
        Registration registration = registerAnswering(ScriptedHttp.NO_RESPONSE);

        assertThat(registration.status()).isEqualTo(RegistrationStatus.INCONCLUSIVE);
        assertThat(registration.exchange()).isEmpty();
    }

    @Test
    void successWithoutAClientIdIsInconclusive() {
        assertThat(registerAnswering(json(201, "{\"redirect_uris\":[\"https://client.example.com/cb\"]}")).status())
                .isEqualTo(RegistrationStatus.INCONCLUSIVE);
    }

    @Test
    void successWithABlankOrNonTextClientIdIsInconclusive() {
        assertThat(registerAnswering(json(201, "{\"client_id\":\" \"}")).status())
                .isEqualTo(RegistrationStatus.INCONCLUSIVE);
        assertThat(new ProbeClientRegistrar(new ScriptedHttp().on("POST", ENDPOINT.toString(),
                json(201, "{\"client_id\":7}")).oauth(), ENDPOINT).register(METADATA).status())
                .isEqualTo(RegistrationStatus.INCONCLUSIVE);
    }

    @Test
    void successWithNonJsonBodyIsInconclusive() {
        Registration registration = registerAnswering(json(201, "<html>registered</html>"));

        assertThat(registration.status()).isEqualTo(RegistrationStatus.INCONCLUSIVE);
        assertThat(registration.exchange()).isPresent();
    }

    @Test
    void readsRfc7592ClientManagementCredentials() {
        Registration registration = registerAnswering(json(201, managed(MANAGED, "rat-1")));

        assertThat(registration.client()).flatMap(RegisteredClient::management)
                .contains(new ClientManagement(URI.create(MANAGED), "rat-1"));
    }

    @Test
    void ignoresClientManagementOffTheRegistrationOriginOrWithoutAToken() {
        assertThat(registerAnswering(json(201, managed("https://internal.example/clients/c1", "rat-1"))).client())
                .flatMap(RegisteredClient::management).isEmpty();
        assertThat(new ProbeClientRegistrar(new ScriptedHttp().on("POST", ENDPOINT.toString(),
                json(201, managed(MANAGED, " "))).oauth(), ENDPOINT).register(METADATA).client())
                .flatMap(RegisteredClient::management).isEmpty();
    }

    @Test
    void deletesEveryManagedClientItRegisteredWithItsAccessToken() {
        http.on("POST", ENDPOINT.toString(), json(201, managed(MANAGED, "rat-1")))
                .on("DELETE", MANAGED, status(204));
        registrar.register(METADATA);
        registrar.register(METADATA);

        ClientCleanup cleanup = registrar.deleteRegisteredClients();

        assertThat(cleanup).isEqualTo(new ClientCleanup(2, 2));
        assertThat(http.sentTo(MANAGED)).hasSize(2).allSatisfy(request -> {
            assertThat(request.method()).isEqualTo("DELETE");
            assertThat(request.headerValue("Authorization")).isEqualTo("Bearer rat-1");
        });
    }

    @Test
    void countsUnmanagedAndRefusedDeletionsAsRemaining() {
        http.on("POST", ENDPOINT.toString(), json(201, managed(MANAGED, "rat-1")))
                .on("DELETE", MANAGED, status(401));
        registrar.register(METADATA);

        assertThat(registrar.deleteRegisteredClients()).isEqualTo(new ClientCleanup(1, 0));
    }

    @Test
    void neverDeletesAClientItDidNotIssueOrTwice() {
        http.on("POST", ENDPOINT.toString(), json(201, ACCEPTED_BODY));
        registrar.register(METADATA);
        registerAnswering(json(400, "{}"));

        assertThat(registrar.deleteRegisteredClients()).isEqualTo(new ClientCleanup(1, 0));
        assertThat(registrar.deleteRegisteredClients()).isEqualTo(new ClientCleanup(0, 0));
        assertThat(http.sent()).extracting(HttpRequest::method).doesNotContain("DELETE");
    }

    @Test
    void cleanupStopsAfterTheServerAnswersTooManyRequests() {
        http.on("POST", ENDPOINT.toString(), json(201, managed(MANAGED, "rat-1")))
                .on("DELETE", MANAGED, status(429));
        registrar.register(METADATA);
        registrar.register(METADATA);

        assertThat(registrar.deleteRegisteredClients()).isEqualTo(new ClientCleanup(2, 0));
        assertThat(http.sentTo(MANAGED)).hasSize(1);
    }

    @Test
    void cleanupSummaryNamesTheCounts() {
        assertThat(new ClientCleanup(3, 2).summary()).contains("2 of 3").contains("RFC 7592");
    }

    @Test
    void retriesWithTheRefreshGrantWhenTheServerRequiresIt() {
        http.on("POST", ENDPOINT.toString(), request -> request.bodyToString().contains("refresh_token")
                ? json(201, ACCEPTED_BODY)
                : json(400, "{\"error\":\"invalid_client_metadata\",\"error_description\":\"grant_types must be "
                        + "authorization_code and refresh_token\"}"));

        Registration registration = registrar.registerAddingRefreshGrantIfRequired(
                ClientMetadata.codeGrant("probe", REDIRECT_URIS));

        assertThat(registration.client()).isPresent();
        assertThat(http.sentTo(ENDPOINT.toString())).hasSize(2);
    }

    @Test
    void registersTheCodeGrantAloneWhenTheServerAcceptsIt() {
        http.on("POST", ENDPOINT.toString(), json(201, ACCEPTED_BODY));

        registrar.registerAddingRefreshGrantIfRequired(ClientMetadata.codeGrant("probe", REDIRECT_URIS));

        assertThat(http.sentTo(ENDPOINT.toString())).singleElement()
                .satisfies(request -> assertThat(request.bodyToString()).doesNotContain("refresh_token"));
    }

    @Test
    void doesNotRetryAnotherRejection() {
        http.on("POST", ENDPOINT.toString(), json(400, "{\"error\":\"invalid_redirect_uri\"}"));

        registrar.registerAddingRefreshGrantIfRequired(ClientMetadata.codeGrant("probe", REDIRECT_URIS));

        assertThat(http.sentTo(ENDPOINT.toString())).hasSize(1);
    }

    private ClientCredentials credentialsAnswering(String body) {
        return registerAnswering(json(201, body)).client().orElseThrow().credentials();
    }

    @Test
    void aClientIssuedNoSecretIsPublic() {
        assertThat(credentialsAnswering(ACCEPTED_BODY)).isEqualTo(ClientCredentials.publicClient("c1"));
    }

    @Test
    void anIssuedSecretIsSentInTheFormWhenTheServerNamesNoneOrPost() {
        assertThat(credentialsAnswering("{\"client_id\":\"c1\",\"client_secret\":\"s1\","
                + "\"token_endpoint_auth_method\":\"none\"}").secret())
                .contains(new ClientSecret("s1", ClientSecretMethod.POST));
        assertThat(credentialsAnswering("{\"client_id\":\"c1\",\"client_secret\":\"s1\","
                + "\"token_endpoint_auth_method\":\"client_secret_post\"}").secret())
                .contains(new ClientSecret("s1", ClientSecretMethod.POST));
    }

    @Test
    void anIssuedSecretIsSentAsBasicWhenTheServerNamesBasicOrNoMethod() {
        assertThat(credentialsAnswering("{\"client_id\":\"c1\",\"client_secret\":\"s1\","
                + "\"token_endpoint_auth_method\":\"client_secret_basic\"}").secret())
                .contains(new ClientSecret("s1", ClientSecretMethod.BASIC));
        assertThat(credentialsAnswering("{\"client_id\":\"c1\",\"client_secret\":\"s1\"}").secret())
                .contains(new ClientSecret("s1", ClientSecretMethod.BASIC));
    }
}
