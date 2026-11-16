package com.mcpscanner.checks.catalog.ssrffilterbypass;

import java.util.Arrays;
import java.util.List;

record Lead(AddressSpelling spelling, SentUrl loopback) {

    static List<Lead> find(FieldSender sender, int targetPort, Refusal refusal) {
        return Arrays.stream(AddressSpelling.values())
                .map(spelling -> new Lead(spelling, sendLoopback(sender, spelling, targetPort)))
                .filter(lead -> lead.loopback().answered() && !refusal.repeatedBy(lead.loopback()))
                .toList();
    }

    private static SentUrl sendLoopback(FieldSender sender, AddressSpelling spelling, int targetPort) {
        return sender.send(ProbeUrl.loopback(spelling.loopbackHost(), targetPort));
    }
}
