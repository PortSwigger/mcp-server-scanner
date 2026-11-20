package com.mcpscanner.checks.catalog.sessionlifecycle;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SessionLifecycleIssuesTest {

    private static final List<String> IDS = List.of("1", "2", "3", "4", "5", "6", "7", "8");
    private static final List<String> WEAKNESSES = List.of("They increase by 1 each time.");

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void aGuessableIssueWithoutHandshakesDoesNotSayAnyAreAttached() {
        GuessableIds guessable = new GuessableIds(IDS, WEAKNESSES, List.of(), Optional.empty(), false);

        assertThat(new SessionLifecycleIssues().guessable(guessable, base()).detail())
                .doesNotContain("attached");
    }

    @Test
    void aGuessableIssueSaysHowManyHandshakesAreAttached() {
        GuessableIds guessable = new GuessableIds(IDS, WEAKNESSES, List.of(base()), Optional.empty(), false);

        assertThat(new SessionLifecycleIssues().guessable(guessable, base()).detail())
                .contains("One of these session handshakes is attached");
    }

    private static HttpRequestResponse base() {
        return HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl("http://target.test/mcp").withMethod("POST"), null);
    }
}
