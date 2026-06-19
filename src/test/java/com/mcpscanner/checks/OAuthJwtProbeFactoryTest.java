package com.mcpscanner.checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.OAuthJwtProbeFactory.JwtProbe;
import com.mcpscanner.mcp.McpObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthJwtProbeFactoryTest {

    private static final List<String> VALID_AUD = List.of("https://server.example/mcp");
    private static final Optional<String> VALID_ISS = Optional.of("https://issuer.example/");

    @Test
    void mintsAllFiveProbesWhenClaimsKnown() {
        List<JwtProbe> probes = new OAuthJwtProbeFactory().mintProbes(VALID_AUD, VALID_ISS);

        assertThat(labels(probes)).containsExactlyInAnyOrder(
                OAuthJwtProbeFactory.LABEL_RANDOM_SIG,
                OAuthJwtProbeFactory.LABEL_WRONG_AUD,
                OAuthJwtProbeFactory.LABEL_WRONG_ISS,
                OAuthJwtProbeFactory.LABEL_EXPIRED,
                OAuthJwtProbeFactory.LABEL_ALG_NONE);
    }

    @Test
    void omitsWrongAudWhenValidAudIsEmpty() {
        List<JwtProbe> probes = new OAuthJwtProbeFactory().mintProbes(List.of(), VALID_ISS);

        assertThat(labels(probes)).doesNotContain(OAuthJwtProbeFactory.LABEL_WRONG_AUD);
        assertThat(labels(probes)).contains(OAuthJwtProbeFactory.LABEL_WRONG_ISS);
    }

    @Test
    void omitsWrongIssWhenValidIssIsEmpty() {
        List<JwtProbe> probes = new OAuthJwtProbeFactory().mintProbes(VALID_AUD, Optional.empty());

        assertThat(labels(probes)).doesNotContain(OAuthJwtProbeFactory.LABEL_WRONG_ISS);
        assertThat(labels(probes)).contains(OAuthJwtProbeFactory.LABEL_WRONG_AUD);
    }

    @Test
    void algNoneTokenBeginsWithExpectedHeaderPrefix() {
        JwtProbe probe = findProbe(OAuthJwtProbeFactory.LABEL_ALG_NONE,
                new OAuthJwtProbeFactory().mintProbes(VALID_AUD, VALID_ISS));

        assertThat(probe.token()).startsWith("eyJhbGciOiJub25lI");
    }

    @Test
    void algNoneTokenHasEmptyThirdSegment() {
        JwtProbe probe = findProbe(OAuthJwtProbeFactory.LABEL_ALG_NONE,
                new OAuthJwtProbeFactory().mintProbes(VALID_AUD, VALID_ISS));

        String[] segments = probe.token().split("\\.", -1);
        assertThat(segments).hasSize(3);
        assertThat(segments[2]).isEmpty();
    }

    @Test
    void signedProbesHaveThreeNonEmptySegments() {
        List<JwtProbe> probes = new OAuthJwtProbeFactory().mintProbes(VALID_AUD, VALID_ISS);
        Set<String> signedLabels = Set.of(
                OAuthJwtProbeFactory.LABEL_RANDOM_SIG,
                OAuthJwtProbeFactory.LABEL_WRONG_AUD,
                OAuthJwtProbeFactory.LABEL_WRONG_ISS,
                OAuthJwtProbeFactory.LABEL_EXPIRED);
        for (JwtProbe probe : probes) {
            if (!signedLabels.contains(probe.label())) {
                continue;
            }
            String[] segments = probe.token().split("\\.", -1);
            assertThat(segments).as(probe.label()).hasSize(3);
            assertThat(segments[0]).as(probe.label() + " header").isNotEmpty();
            assertThat(segments[1]).as(probe.label() + " payload").isNotEmpty();
            assertThat(segments[2]).as(probe.label() + " signature").isNotEmpty();
        }
    }

    @Test
    void distinctFactoryInstancesProduceDifferentSignatures() {
        JwtProbe first = findProbe(OAuthJwtProbeFactory.LABEL_RANDOM_SIG,
                new OAuthJwtProbeFactory().mintProbes(VALID_AUD, VALID_ISS));
        JwtProbe second = findProbe(OAuthJwtProbeFactory.LABEL_RANDOM_SIG,
                new OAuthJwtProbeFactory().mintProbes(VALID_AUD, VALID_ISS));

        String firstSig = first.token().split("\\.")[2];
        String secondSig = second.token().split("\\.")[2];
        assertThat(firstSig).isNotEqualTo(secondSig);
    }

    @Test
    void mintProbesPreservesMultiAudOnRandomSigExpiredAndAlgNone() {
        OAuthJwtProbeFactory factory = new OAuthJwtProbeFactory();

        List<JwtProbe> probes = factory.mintProbes(
                List.of("https://other-rs/", "https://this-mcp/"),
                Optional.of("https://issuer.example/"));

        JwtProbe randomSig = findProbe(OAuthJwtProbeFactory.LABEL_RANDOM_SIG, probes);
        assertThat(audClaim(randomSig.token()))
                .containsExactly("https://other-rs/", "https://this-mcp/");

        JwtProbe expired = findProbe(OAuthJwtProbeFactory.LABEL_EXPIRED, probes);
        assertThat(audClaim(expired.token()))
                .containsExactly("https://other-rs/", "https://this-mcp/");

        JwtProbe algNone = findProbe(OAuthJwtProbeFactory.LABEL_ALG_NONE, probes);
        assertThat(audClaim(algNone.token()))
                .containsExactly("https://other-rs/", "https://this-mcp/");
    }

    private static List<String> audClaim(String token) {
        try {
            String payloadSegment = token.split("\\.", -1)[1];
            int remainder = payloadSegment.length() % 4;
            String padded = remainder == 0 ? payloadSegment : payloadSegment + "=".repeat(4 - remainder);
            byte[] decoded = Base64.getUrlDecoder().decode(padded);
            JsonNode payload = McpObjectMapper.INSTANCE.readTree(new String(decoded, StandardCharsets.UTF_8));
            JsonNode aud = payload.path("aud");
            List<String> values = new ArrayList<>();
            if (aud.isTextual()) {
                values.add(aud.asText());
            } else if (aud.isArray()) {
                aud.forEach(node -> values.add(node.asText()));
            }
            return values;
        } catch (Exception e) {
            throw new AssertionError("Failed to decode aud claim from " + token, e);
        }
    }

    private static List<String> labels(List<JwtProbe> probes) {
        return probes.stream().map(JwtProbe::label).collect(Collectors.toList());
    }

    private static JwtProbe findProbe(String label, List<JwtProbe> probes) {
        return probes.stream()
                .filter(p -> p.label().equals(label))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Probe " + label + " not minted"));
    }
}
