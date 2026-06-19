package com.mcpscanner.checks;

import com.mcpscanner.checks.JwtShapeDetector.JwtClaims;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class JwtShapeDetectorTest {

    @Test
    void isJwtShapeAcceptsValidThreeSegmentBase64Url() {
        String header = encode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        String payload = encode("{\"sub\":\"x\"}");
        String token = header + "." + payload + ".signature";

        assertThat(JwtShapeDetector.isJwtShape(token)).isTrue();
    }

    @Test
    void isJwtShapeRejectsTwoSegmentToken() {
        String header = encode("{\"alg\":\"RS256\"}");
        String payload = encode("{\"sub\":\"x\"}");
        assertThat(JwtShapeDetector.isJwtShape(header + "." + payload)).isFalse();
    }

    @Test
    void isJwtShapeRejectsFourSegmentToken() {
        String header = encode("{\"alg\":\"RS256\"}");
        String payload = encode("{\"sub\":\"x\"}");
        assertThat(JwtShapeDetector.isJwtShape(header + "." + payload + ".sig.extra")).isFalse();
    }

    @Test
    void isJwtShapeRejectsNonBase64UrlCharacters() {
        assertThat(JwtShapeDetector.isJwtShape("aaa+bbb.ccc.ddd")).isFalse();
        assertThat(JwtShapeDetector.isJwtShape("aaa/bbb.ccc.ddd")).isFalse();
    }

    @Test
    void isJwtShapeRejectsHeaderWithoutAlg() {
        String header = encode("{\"typ\":\"JWT\"}");
        String payload = encode("{\"sub\":\"x\"}");
        String token = header + "." + payload + ".sig";

        assertThat(JwtShapeDetector.isJwtShape(token)).isFalse();
    }

    @Test
    void isJwtShapeRejectsTokenWithNonJsonPayload() {
        String header = encode("{\"alg\":\"RS256\"}");
        String payload = encode("just-a-string");
        String token = header + "." + payload + ".sig";

        assertThat(JwtShapeDetector.isJwtShape(token)).isFalse();
    }

    @Test
    void isJwtShapeRejectsTokenWithJsonArrayPayload() {
        String header = encode("{\"alg\":\"RS256\"}");
        String payload = encode("[1,2,3]");
        String token = header + "." + payload + ".sig";

        assertThat(JwtShapeDetector.isJwtShape(token)).isFalse();
    }

    @Test
    void extractClaimsHandlesMissingPadding() {
        // payload "{\"sub\":\"abc\"}" — base64url-encoded length will need padding to be a multiple of 4
        String header = encode("{\"alg\":\"RS256\"}");
        String payloadJson = "{\"sub\":\"abc\"}";
        String payload = encodeWithoutPadding(payloadJson);
        String token = header + "." + payload + ".sig";

        Optional<JwtClaims> claims = JwtShapeDetector.extractClaims(token);

        assertThat(claims).isPresent();
    }

    @Test
    void extractClaimsWrapsScalarAudInSingletonList() {
        String token = buildToken("{\"alg\":\"RS256\"}", "{\"aud\":\"resource-1\"}");

        JwtClaims claims = JwtShapeDetector.extractClaims(token).orElseThrow();

        assertThat(claims.aud()).containsExactly("resource-1");
    }

    @Test
    void extractClaimsReturnsAllAudValuesForArrayClaim() {
        String token = buildToken("{\"alg\":\"RS256\"}", "{\"aud\":[\"first\",\"second\"]}");

        JwtClaims claims = JwtShapeDetector.extractClaims(token).orElseThrow();

        assertThat(claims.aud()).containsExactly("first", "second");
    }

    @Test
    void extractClaimsReturnsEmptyAudAndIssWhenMissing() {
        String token = buildToken("{\"alg\":\"RS256\"}", "{\"sub\":\"x\"}");

        JwtClaims claims = JwtShapeDetector.extractClaims(token).orElseThrow();

        assertThat(claims.aud()).isEmpty();
        assertThat(claims.iss()).isEmpty();
    }

    @Test
    void extractClaimsParsesIss() {
        String token = buildToken("{\"alg\":\"RS256\"}", "{\"iss\":\"https://issuer.example/\"}");

        JwtClaims claims = JwtShapeDetector.extractClaims(token).orElseThrow();

        assertThat(claims.iss()).contains("https://issuer.example/");
    }

    @Test
    void extractClaimsRejectsNonObjectPayload() {
        String token = buildToken("{\"alg\":\"RS256\"}", "\"just-a-string\"");

        assertThat(JwtShapeDetector.extractClaims(token)).isEmpty();
    }

    private static String buildToken(String headerJson, String payloadJson) {
        return encode(headerJson) + "." + encode(payloadJson) + ".sig";
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String encodeWithoutPadding(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
