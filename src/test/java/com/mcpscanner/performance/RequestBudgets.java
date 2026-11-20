package com.mcpscanner.performance;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

public final class RequestBudgets {

    private static final String TABLE = """
            Connect, modern HTTP                                            | 1
            Connect, initialize-based HTTP                                  | 2
            Connect, SSE                                                    | 3
            Browser consent fallback, server that asks for consent          | 2  | opt-in: register and delete one probe client
            Browser consent fallback, server that skips consent             | 4  | opt-in: a second probe client after the first got a code
            Discovery, 10 tools in pages of 3                               | 7
            Scan of one tool call, command-injection                        | 156
            Scan of one tool call, cross-client-response-leak               | 4
            Scan of one tool call, crossidentityaccess                      | 0
            Scan of one tool call, downstream-route-escape                  | 184
            Scan of one tool call, file-traversal                           | 255
            Scan of one tool call, jwt-validation                           | 0
            Scan of one tool call, oauth-authorization-consent              | 5
            Scan of one tool call, oauth-consent-structure-reflection       | 5
            Scan of one tool call, oauth-redirect-policy                    | 5
            Scan of one tool call, oauth-refresh-grant                      | 0
            Scan of one tool call, origin-host-admission                    | 0
            Scan of one tool call, outbound-request                         | 25
            Scan of one tool call, session-lifecycle                        | 17
            Scan of one tool call, session-binding                          | 0
            Scan of one tool call, sql-injection                            | 36
            Scan of one tool call, sibling-route-auth-parity                | 0
            Scan of one tool call, ssrf-filter-bypass                       | 0
            Scan of one tool call, unauthenticated-request-execution        | 14
            Generated calls for one tool with two pattern-bound optional arguments | 3
            Signed-in consent trial, benign server                          | 20 | opt-in: 4 discovery, 3 probe registrations, 5 two-hop authorization walks, 3 deletions
            Check access per item, stateless server, same credentials       | 4  | +1 fake-token call per item
            Check access per item, stateless server, distinct credentials   | 7  | +1 fake-token call per item
            Check access per item, stateful server, same credentials        | 6  | +2 fake-token session attempt and call per item
            Check access per item, stateful server, distinct credentials    | 10 | +2 fake-token session attempt and call per item
            Check access per item, stateless server, refused at the captured version | 10 | +1 fake-token call per item
            Check access run, synthetic listings, initialize-based HTTP     | 14 | No credential and fake-token isolated discovery, 7 each, once per run
            """;

    private static final Map<String, Integer> BUDGETS = Arrays.stream(TABLE.split("\n"))
            .map(row -> row.split("\\|"))
            .collect(Collectors.toMap(cells -> cells[0].trim(), cells -> Integer.parseInt(cells[1].trim())));

    private RequestBudgets() {
    }

    public static void assertWithin(String operation, List<String> sent) {
        int budget = budgetOf(operation);
        assertThat(sent.size())
                .as("%s sent %d requests, budget %d:%n%s", operation, sent.size(), budget, breakdown(sent))
                .isLessThanOrEqualTo(budget);
    }

    private static String breakdown(List<String> sent) {
        return sent.stream()
                .collect(Collectors.groupingBy(Function.identity(), LinkedHashMap::new, Collectors.counting()))
                .entrySet().stream()
                .map(request -> String.format("  %4d × %s", request.getValue(), request.getKey()))
                .collect(Collectors.joining("\n"));
    }

    private static int budgetOf(String operation) {
        Integer budget = BUDGETS.get(operation);
        assertThat(budget).as("no budget row for '%s' in RequestBudgets", operation).isNotNull();
        return budget;
    }
}
