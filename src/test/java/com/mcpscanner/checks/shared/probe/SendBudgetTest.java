package com.mcpscanner.checks.shared.probe;

import com.mcpscanner.mcp.RateLimitStop;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SendBudgetTest {

    @Test
    void affordsSendsUpToItsLimitThenIsExhausted() {
        SendBudget budget = new SendBudget(3);
        budget.record(Optional.empty());

        assertThat(budget.affords(2)).isTrue();
        assertThat(budget.affords(3)).isFalse();
        budget.record(Optional.empty());
        budget.record(Optional.empty());
        assertThat(budget.exhausted()).isTrue();
        assertThat(budget.sent()).isEqualTo(3);
    }

    @Test
    void aSpentQuotaAloneIsNotATooManyRequestsAnswer() {
        SendBudget budget = new SendBudget(10);
        budget.record(Optional.of(RateLimitStop.QUOTA_SPENT));

        assertThat(budget.rateLimitStop()).contains(RateLimitStop.QUOTA_SPENT);
        assertThat(budget.answeredTooManyRequests()).isFalse();
        assertThat(budget.exhausted()).isTrue();
    }

    @Test
    void aRateLimitedReplyExhaustsItAtOnce() {
        SendBudget budget = new SendBudget(10);
        budget.record(Optional.of(RateLimitStop.QUOTA_SPENT));
        budget.record(Optional.of(RateLimitStop.TOO_MANY_REQUESTS));

        assertThat(budget.rateLimitStop()).contains(RateLimitStop.TOO_MANY_REQUESTS);
        assertThat(budget.answeredTooManyRequests()).isTrue();
        assertThat(budget.exhausted()).isTrue();
        assertThat(budget.affords(1)).isFalse();
    }
}
