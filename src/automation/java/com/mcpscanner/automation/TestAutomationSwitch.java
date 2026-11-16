package com.mcpscanner.automation;

import java.util.OptionalInt;
import java.util.function.UnaryOperator;

public record TestAutomationSwitch(UnaryOperator<String> properties) {

    public static final String PORT_PROPERTY = "mcpscanner.testAutomation.port";

    public static TestAutomationSwitch fromSystemProperties() {
        return new TestAutomationSwitch(System::getProperty);
    }

    public OptionalInt port() {
        String value = properties.apply(PORT_PROPERTY);
        if (value == null || value.isBlank()) {
            return OptionalInt.empty();
        }
        try {
            return OptionalInt.of(Integer.parseInt(value.strip()));
        } catch (NumberFormatException notANumber) {
            throw new IllegalArgumentException(PORT_PROPERTY + " must be a port number, got " + value);
        }
    }
}
