package com.mcpscanner.access.listing;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.access.SyntheticCall;
import com.mcpscanner.checks.api.crossidentity.OperationReply;

import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Stream;

final class ListingEvidence {

    private final Function<String, List<HttpRequestResponse>> toolsLists;

    ListingEvidence(Function<String, List<HttpRequestResponse>> toolsLists) {
        this.toolsLists = toolsLists;
    }

    List<HttpRequestResponse> of(ListingFinding finding) {
        Stream<ToolList> listed = Stream.concat(finding.exceeded().stream(), Stream.of(finding.synthetic()));
        Stream<HttpRequestResponse> lists = listed.flatMap(list -> toolsLists.apply(list.id()).stream());
        Stream<HttpRequestResponse> calls = finding.confirmations().stream().map(SyntheticCall::reply)
                .map(OperationReply::exchange).filter(Objects::nonNull);
        return Stream.concat(lists, calls).toList();
    }
}
