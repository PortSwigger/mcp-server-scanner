package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import com.mcpscanner.checks.registry.CheckInstrumentation;
import com.mcpscanner.scan.request.ScanMessageRenderer;

import java.util.ServiceLoader;
import java.util.function.UnaryOperator;

interface ExtensionAutomation {

    ExtensionAutomation NONE = new ExtensionAutomation() {
    };

    static ExtensionAutomation installed() {
        return ServiceLoader.load(ExtensionAutomation.class, ExtensionAutomation.class.getClassLoader())
                .findFirst()
                .orElse(NONE);
    }

    default CheckInstrumentation instrumentation() {
        return CheckInstrumentation.NONE;
    }

    default UnaryOperator<ScanMessageRenderer> launchRenderer() {
        return UnaryOperator.identity();
    }

    default void startIfSwitchedOn(MontoyaApi api, ExtensionFoundation foundation, ConnectionWiring connection,
                                   ScanningWiring scanning, AccessWiring access, MiningWiring mining,
                                   ShutdownHooks shutdown) {
    }
}
