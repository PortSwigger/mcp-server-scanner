package com.mcpscanner.checks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.mcp.McpObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class OAuthJwtProbeFactory {

    public record JwtProbe(String label, String token) {}

    public static final String LABEL_RANDOM_SIG = "RANDOM_SIG";
    public static final String LABEL_WRONG_AUD = "WRONG_AUD";
    public static final String LABEL_WRONG_ISS = "WRONG_ISS";
    public static final String LABEL_EXPIRED = "EXPIRED";
    public static final String LABEL_ALG_NONE = "ALG_NONE";

    private static final String ATTACKER_AUD = "https://attacker.example/mcp";
    private static final String ATTACKER_ISS = "https://attacker.example/";
    private static final long FUTURE_EXP_SECONDS = 3600L;
    private static final long EXPIRED_EXP_EPOCH = 1L;

    private final RSAPrivateKey signingKey;

    public OAuthJwtProbeFactory() {
        this.signingKey = generateRsaKeyPair();
    }

    public List<JwtProbe> mintProbes(List<String> validAud, Optional<String> validIss) {
        List<JwtProbe> probes = new ArrayList<>();
        probes.add(new JwtProbe(LABEL_RANDOM_SIG, signedJwt(validAud, validIss, futureExpiry())));
        if (!validAud.isEmpty()) {
            probes.add(new JwtProbe(LABEL_WRONG_AUD,
                    signedJwt(List.of(ATTACKER_AUD), validIss, futureExpiry())));
        }
        validIss.ifPresent(iss -> probes.add(
                new JwtProbe(LABEL_WRONG_ISS, signedJwt(validAud, Optional.of(ATTACKER_ISS), futureExpiry()))));
        probes.add(new JwtProbe(LABEL_EXPIRED, signedJwt(validAud, validIss, new Date(EXPIRED_EXP_EPOCH * 1000L))));
        probes.add(new JwtProbe(LABEL_ALG_NONE, algNoneJwt(validAud, validIss, futureExpiry())));
        return probes;
    }

    private static RSAPrivateKey generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            return (RSAPrivateKey) pair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA key generation unavailable", e);
        }
    }

    private String signedJwt(List<String> aud, Optional<String> iss, Date exp) {
        try {
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .subject("mcp-scanner-probe")
                    .expirationTime(exp);
            if (!aud.isEmpty()) {
                claims.audience(aud);
            }
            iss.ifPresent(claims::issuer);
            SignedJWT signed = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims.build());
            signed.sign(new RSASSASigner(signingKey));
            return signed.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign JWT probe", e);
        }
    }

    private static String algNoneJwt(List<String> aud, Optional<String> iss, Date exp) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "none");
        header.put("typ", "JWT");

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "mcp-scanner-probe");
        claims.put("exp", exp.getTime() / 1000L);
        if (!aud.isEmpty()) {
            claims.put("aud", aud.size() == 1 ? aud.get(0) : aud);
        }
        iss.ifPresent(value -> claims.put("iss", value));

        return base64Url(toJson(header)) + "." + base64Url(toJson(claims)) + ".";
    }

    private static Date futureExpiry() {
        return Date.from(Instant.now().plusSeconds(FUTURE_EXP_SECONDS));
    }

    private static String toJson(Map<String, Object> value) {
        try {
            ObjectMapper mapper = McpObjectMapper.INSTANCE;
            return mapper.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize JWT segment", e);
        }
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
