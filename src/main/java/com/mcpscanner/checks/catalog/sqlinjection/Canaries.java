package com.mcpscanner.checks.catalog.sqlinjection;

import com.mcpscanner.checks.shared.random.RandomHex;

import java.security.SecureRandom;

class Canaries {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int OPERAND_FLOOR = 1_000;
    private static final int OPERAND_SPAN = 9_000;

    String token() {
        return "q" + RandomHex.of(4);
    }

    StatementCanary statement() {
        return new StatementCanary(operand(), operand());
    }

    private static long operand() {
        return OPERAND_FLOOR + RANDOM.nextInt(OPERAND_SPAN);
    }
}
