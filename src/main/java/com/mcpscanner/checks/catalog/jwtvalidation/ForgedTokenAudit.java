package com.mcpscanner.checks.catalog.jwtvalidation;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.RateLimitedSends;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.auth.oracle.OracleVerdict;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

final class ForgedTokenAudit {

    static final String MALFORMED_TOKEN = "mcp-scanner-malformed-token";

    private final ForgeryCatalog catalog;
    private final PublishedKeyDiscovery keyDiscovery;
    private final BearerPlacement placement;
    private final BaselineEquivalenceOracle oracle;
    private final Clock clock;
    private final CheckLog log;

    ForgedTokenAudit(ForgeryCatalog catalog, PublishedKeyDiscovery keyDiscovery, BearerPlacement placement,
                     BaselineEquivalenceOracle oracle, Clock clock, CheckLog log) {
        this.catalog = catalog;
        this.keyDiscovery = keyDiscovery;
        this.placement = placement;
        this.oracle = oracle;
        this.clock = clock;
        this.log = log;
    }

    Optional<ForgedTokenFindings> run(HttpRequest seed, CompactJwt captured, String bearer, RateLimitedSends sends) {
        Http http = sends.probes();
        HttpRequestResponse baseline = http.sendRequest(placement.withBearer(seed, bearer));
        RefusalControls controls = sendRefusalControls(seed, http);
        AcceptanceJudge judge = new AcceptanceJudge(oracle, baseline, controls.both());
        OracleVerdict verdict = judge.baselineVerdict();
        if (!verdict.isHit()) {
            log.notRun(SkipSubject.of(seed), baselineSkip(verdict, baseline));
            return Optional.empty();
        }
        ForgeryContext context = new ForgeryContext(captured,
                () -> keyDiscovery.discover(seed.url(), captured, new OAuthHttp(http)));
        return new Probing(seed, captured, sends, judge).run(catalog.attemptsFor(context))
                .map(probing -> new ForgedTokenFindings(baseline, controls.malformedBearer(), probing.accepted,
                        probing.claimProbes));
    }

    private static SkipReason baselineSkip(OracleVerdict verdict, HttpRequestResponse baseline) {
        return switch (verdict) {
            case CONTROL_NOT_REFUSED -> SkipReason.prerequisiteMissing("the request is answered without a valid credential");
            case NO_REFUSAL_CONTROLS -> SkipReason.prerequisiteMissing("no refusal control was answered");
            default -> baseline == null || baseline.response() == null
                    ? SkipReason.transportFailure("the replay with the captured JWT got no response")
                    : SkipReason.prerequisiteMissing("the replay with the captured JWT did not succeed");
        };
    }

    private RefusalControls sendRefusalControls(HttpRequest seed, Http http) {
        return new RefusalControls(
                http.sendRequest(placement.withoutCredential(seed)),
                http.sendRequest(placement.withBearer(seed, MALFORMED_TOKEN)));
    }

    private final class Probing {

        private final HttpRequest seed;
        private final CompactJwt captured;
        private final RateLimitedSends sends;
        private final AcceptanceJudge judge;
        private final List<AcceptedForgery> accepted = new ArrayList<>();
        private List<ClaimProbe> claimProbes = List.of();
        private boolean controlsLifted;

        private Probing(HttpRequest seed, CompactJwt captured, RateLimitedSends sends, AcceptanceJudge judge) {
            this.seed = seed;
            this.captured = captured;
            this.sends = sends;
            this.judge = judge;
        }

        private Optional<Probing> run(List<ForgeryAttempt> attempts) {
            for (ForgeryAttempt attempt : attempts) {
                tryAttempt(attempt).ifPresent(this::record);
            }
            if (controlsLifted) {
                log.notRun("the accepted forgeries for " + SkipSubject.of(seed), SkipReason.prerequisiteMissing(
                        "the refusal controls were no longer refused after a forgery was accepted"));
            }
            return accepted.isEmpty() ? Optional.empty() : Optional.of(this);
        }

        private void record(AcceptedAttempt acceptedAttempt) {
            boolean alreadyReported = accepted.stream()
                    .anyMatch(forgery -> forgery.description().equals(acceptedAttempt.forgery().description()));
            if (alreadyReported) {
                return;
            }
            accepted.add(acceptedAttempt.forgery());
            if (claimProbes.isEmpty()) {
                claimProbes = probeClaims(acceptedAttempt.signature());
            }
        }

        private Optional<AcceptedAttempt> tryAttempt(ForgeryAttempt attempt) {
            HttpRequestResponse candidate = send(sends.probes(), attempt.candidate(), captured.claims());
            if (!judge.accepts(candidate)) {
                return Optional.empty();
            }
            List<HttpRequestResponse> stillRefused = sendRefusalControls(seed, sends.confirmations()).both();
            if (!judge.accepts(candidate, stillRefused)) {
                controlsLifted = true;
                return Optional.empty();
            }
            if (attempt.wrongKeyControl().isEmpty()) {
                return Optional.of(acceptedAs(attempt.candidate(), candidate, Optional.empty()));
            }
            ForgedSignature wrongKey = attempt.wrongKeyControl().get();
            HttpRequestResponse control = send(sends.confirmations(), wrongKey, captured.claims());
            if (judge.accepts(control, stillRefused)) {
                return Optional.of(acceptedAs(wrongKey, control, Optional.empty()));
            }
            return Optional.of(acceptedAs(attempt.candidate(), candidate, Optional.of(control)));
        }

        private AcceptedAttempt acceptedAs(ForgedSignature signature, HttpRequestResponse exchange,
                                           Optional<HttpRequestResponse> refusedWrongKeyControl) {
            return new AcceptedAttempt(signature,
                    new AcceptedForgery(signature.description(), exchange, refusedWrongKeyControl));
        }

        private List<ClaimProbe> probeClaims(ForgedSignature signature) {
            return Arrays.stream(ClaimMutation.values())
                    .map(mutation -> {
                        HttpRequestResponse exchange = send(sends.confirmations(), signature,
                                mutation.applyTo(captured.claims(), clock));
                        return new ClaimProbe(mutation, exchange, judge.accepts(exchange));
                    })
                    .toList();
        }

        private HttpRequestResponse send(Http http, ForgedSignature signature, ObjectNode claims) {
            return http.sendRequest(placement.withBearer(seed, signature.sign(claims)));
        }
    }

    private record AcceptedAttempt(ForgedSignature signature, AcceptedForgery forgery) {
    }
}
