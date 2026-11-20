package com.mcpscanner.checks.api;

import java.util.Objects;

public record SkipReason(Kind kind, String detail) {

    public enum Kind {
        DISABLED("check disabled", false),
        NOTIFICATION("notification gets no reply", false),
        ALREADY_AUDITED("already audited on this connection", false),
        NOT_APPLICABLE("not applicable", false),
        PREREQUISITE_MISSING("prerequisite missing", false),
        RATE_LIMITED("rate limited", true),
        BUDGET_EXHAUSTED("request budget used up", true),
        TRANSPORT_FAILURE("transport failure", true),
        STREAMED_REPLY("streamed reply withheld by Burp", true),
        SCAN_CANCELLED("scan cancelled", false),
        EXTENSION_UNLOADED("extension unloaded", false);

        private final String label;
        private final boolean interruptsProbing;

        Kind(String label, boolean interruptsProbing) {
            this.label = label;
            this.interruptsProbing = interruptsProbing;
        }

        public String label() {
            return label;
        }

        String verb() {
            return interruptsProbing ? "stopped" : "skipped";
        }
    }

    public SkipReason {
        Objects.requireNonNull(kind, "kind must not be null");
        detail = detail == null ? "" : detail;
    }

    public static SkipReason disabled() {
        return new SkipReason(Kind.DISABLED, "");
    }

    public static SkipReason notification() {
        return new SkipReason(Kind.NOTIFICATION, "");
    }

    public static SkipReason alreadyAudited(String detail) {
        return new SkipReason(Kind.ALREADY_AUDITED, detail);
    }

    public static SkipReason notApplicable(String detail) {
        return new SkipReason(Kind.NOT_APPLICABLE, detail);
    }

    public static SkipReason prerequisiteMissing(String detail) {
        return new SkipReason(Kind.PREREQUISITE_MISSING, detail);
    }

    public static SkipReason rateLimited() {
        return new SkipReason(Kind.RATE_LIMITED, "the server answered HTTP 429");
    }

    public static SkipReason quotaSpent() {
        return new SkipReason(Kind.RATE_LIMITED, "the server said no requests remain in its rate limit");
    }

    public static SkipReason budgetExhausted(String detail) {
        return new SkipReason(Kind.BUDGET_EXHAUSTED, detail);
    }

    public static SkipReason transportFailure(String detail) {
        return new SkipReason(Kind.TRANSPORT_FAILURE, detail);
    }

    public static SkipReason streamedReply(String detail) {
        return new SkipReason(Kind.STREAMED_REPLY, detail);
    }

    public static SkipReason scanCancelled() {
        return new SkipReason(Kind.SCAN_CANCELLED, "");
    }

    public static SkipReason extensionUnloaded() {
        return new SkipReason(Kind.EXTENSION_UNLOADED, "");
    }

    public String text() {
        return detail.isBlank() ? kind.label() : kind.label() + ": " + detail;
    }

    String line(String subject) {
        return kind.verb() + " " + subject + " (" + text() + ")";
    }
}
