package com.mcpscanner.access.mining;

import com.mcpscanner.config.ResourceCap;

import java.util.Optional;

final class RequestAllowance {

    private final int limit;
    private final boolean userCeiling;
    private int committed;
    private int sent;
    private boolean exhausted;

    private RequestAllowance(int limit, boolean userCeiling) {
        this.limit = limit;
        this.userCeiling = userCeiling;
    }

    static RequestAllowance of(MiningSettings settings, int planned) {
        boolean ceilingBinds = settings.hasRequestCeiling() && settings.requestCeiling() < planned;
        return new RequestAllowance(ceilingBinds ? settings.requestCeiling() : planned, ceilingBinds);
    }

    synchronized boolean reserve(int sends) {
        if (committed + sends > limit) {
            exhausted = true;
            return false;
        }
        committed += sends;
        return true;
    }

    synchronized void recordSend() {
        sent++;
    }

    synchronized int sent() {
        return sent;
    }

    synchronized boolean exhausted() {
        return exhausted;
    }

    synchronized Optional<MiningWarning> warning(String identityId) {
        return exhausted ? Optional.of(new MiningWarning(MiningWarning.Kind.REQUEST_LIMIT, identityId, detail()))
                : Optional.empty();
    }

    private String detail() {
        return userCeiling
                ? "stopped at the \"" + ResourceCap.MINING_REQUESTS_PER_USER.label() + "\" limit after " + sent
                        + " requests; raise or clear it in the extension's settings to collect every ID"
                : "stopped after " + sent + " requests, the most its collecting passes need";
    }
}
