package com.mcpscanner.checks.registry;

import burp.api.montoya.scanner.Scanner;

public interface ManagedCheck {

    CheckDescriptor descriptor();

    void registerWith(Scanner scanner);
}
