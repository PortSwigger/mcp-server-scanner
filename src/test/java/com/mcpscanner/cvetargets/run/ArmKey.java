package com.mcpscanner.cvetargets.run;

public record ArmKey(String check, String target, String arm) {

    static ArmKey of(ArmResult result) {
        return new ArmKey(result.check(), result.target(), result.arm());
    }

    String text() {
        return check + "/" + target + "/" + arm;
    }
}
