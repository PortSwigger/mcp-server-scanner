package com.mcpscanner.access.comparison;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.OperationReply;

import java.util.Map;

record SyntheticReplies(Map<String, OperationReply> replies, Outcomes outcomes) {

    OperationReply noCredential() {
        return replies.getOrDefault(Principal.ANONYMOUS_ID, OperationReply.none());
    }
}
