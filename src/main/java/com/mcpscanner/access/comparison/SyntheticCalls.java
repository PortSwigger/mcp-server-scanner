package com.mcpscanner.access.comparison;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.access.SyntheticCall;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.OperationReply;
import com.mcpscanner.checks.api.crossidentity.OperationSeed;
import com.mcpscanner.checks.api.crossidentity.SessionAdmission;
import com.mcpscanner.mcp.McpHeaders;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

final class SyntheticCalls {

    private final List<Principal> principals;
    private final ComparisonContext context;
    private final Consumer<SyntheticCall> calls;

    SyntheticCalls(List<Principal> principals, ComparisonContext context, Consumer<SyntheticCall> calls) {
        this.principals = principals;
        this.context = context;
        this.calls = calls;
    }

    SyntheticReplies call(OperationSeed seed, OperationReply ownerReply, Outcomes outcomes, PrincipalFanOut fanOut) {
        Map<String, OperationReply> replies = new LinkedHashMap<>();
        fanOut.each(principals, principal -> call(principal, seed, ownerReply, outcomes))
                .forEach((principal, reply) -> replies.put(principal.id(), reply));
        return new SyntheticReplies(replies, outcomes);
    }

    private OperationReply call(Principal principal, OperationSeed seed, OperationReply ownerReply,
                                Outcomes outcomes) {
        OperationReply reply = reply(principal, seed);
        AccessOutcome outcome = Outcomes.synthetic(reply, ownerReply);
        outcomes.recordSynthetic(principal, outcome);
        calls.accept(new SyntheticCall(seed.item(), principal, outcome, reply));
        return reply;
    }

    private OperationReply reply(Principal principal, OperationSeed seed) {
        HttpRequest sessionless = context.requests().as(principal, seed.request())
                .withRemovedHeader(McpHeaders.SESSION_ID);
        SessionAdmission admission = context.sessions().admit(principal.id(), sessionless, seed.stateful());
        return context.transport().reply(admission.request().orElse(sessionless));
    }
}
