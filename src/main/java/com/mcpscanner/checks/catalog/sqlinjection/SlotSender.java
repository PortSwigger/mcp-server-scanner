package com.mcpscanner.checks.catalog.sqlinjection;

@FunctionalInterface
interface SlotSender {

    Probe send(ValueSlot slot, String rewritten);
}
