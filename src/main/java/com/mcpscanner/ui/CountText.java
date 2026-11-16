package com.mcpscanner.ui;

import com.mcpscanner.config.ResourceCap;

import java.util.OptionalLong;

final class CountText implements CapValueText {

    @Override
    public String format(long value) {
        return Long.toString(value);
    }

    @Override
    public OptionalLong parse(String typed) {
        try {
            return OptionalLong.of(Long.parseLong(typed.trim()));
        } catch (NumberFormatException notANumber) {
            return OptionalLong.empty();
        }
    }

    @Override
    public String invalidHint(ResourceCap cap) {
        return "Enter a whole number from " + cap.minValue() + " to " + cap.maxValue() + ", or leave blank for the default ("
                + cap.defaultValue() + ").";
    }
}
