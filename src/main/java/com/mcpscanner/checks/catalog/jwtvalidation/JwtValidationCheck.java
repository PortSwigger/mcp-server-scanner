package com.mcpscanner.checks.catalog.jwtvalidation;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.RateLimitedProbing;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;

import java.util.List;
import java.util.Optional;

public final class JwtValidationCheck implements HostCheck {

    private final BearerJwtLocator locator;
    private final ForgedTokenAudit audit;
    private final JwtValidationIssues issues;
    private final CheckLog log;

    JwtValidationCheck(BearerJwtLocator locator, ForgedTokenAudit audit, CheckLog log) {
        this.locator = locator;
        this.audit = audit;
        this.log = log;
        this.issues = new JwtValidationIssues(JwtValidationDescriptor.DESCRIPTOR);
    }

    @Override
    public CheckDescriptor descriptor() {
        return JwtValidationDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean appliesTo(HttpRequestResponse hostBaseRequestResponse) {
        HttpRequest request = hostBaseRequestResponse.request();
        return ReplayableCall.isReplayable(hostBaseRequestResponse) && locator.locate(request).isPresent();
    }

    @Override
    public String appliesOnlyTo() {
        return "replayable MCP requests carrying a JWT";
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse hostBaseRequestResponse, Http http) {
        HttpRequest seed = hostBaseRequestResponse.request();
        Optional<String> bearer = locator.locate(seed);
        Optional<CompactJwt> captured = bearer.flatMap(CompactJwt::parse);
        String subject = SkipSubject.of(seed);
        if (captured.isEmpty()) {
            log.notRun(subject, SkipReason.prerequisiteMissing("the bearer credential is not a compact JWT"));
            return List.of();
        }
        return new RateLimitedProbing(log).run(subject, http, sends ->
                audit.run(seed, captured.get(), bearer.get(), sends).map(issues::create).stream().toList());
    }
}
