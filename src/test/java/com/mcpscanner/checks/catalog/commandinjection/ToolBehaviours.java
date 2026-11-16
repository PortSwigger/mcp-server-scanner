package com.mcpscanner.checks.catalog.commandinjection;

import com.mcpscanner.checks.catalog.commandinjection.SimulatedToolServer.ToolReply;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

final class ToolBehaviours {

    private static final Pattern ARITHMETIC = Pattern.compile("printf mcp%s \\$\\(\\((\\d+)\\+(\\d+)\\)\\)");
    private static final Pattern QUOTED_ARITHMETIC = Pattern.compile("printf mcp%s '(\\$\\(\\(\\d+\\+\\d+\\)\\))'");
    private static final Pattern PRINTED_NUMBER = Pattern.compile("printf mcp%s '?(\\d+)'?");
    private static final Pattern ANY_ARITHMETIC = Pattern.compile("\\$\\(\\((\\d+)\\+(\\d+)\\)\\)");
    private static final Pattern PYTHON_DECODER =
            Pattern.compile("^__import__\\('builtins'\\)\\.bytes\\(\\[([\\d,]+)]\\)\\.decode\\(\\)$");
    private static final Pattern PYTHON_SINGLE_QUOTE_SPLICE =
            Pattern.compile("^(.*)'\\+__import__\\('builtins'\\)\\.bytes\\(\\[([\\d,]+)]\\)\\.decode\\(\\)\\+'$");
    private static final Pattern PYTHON_CODES = Pattern.compile("bytes\\(\\[([\\d,]+)]\\)");
    private static final Pattern STRING_LITERAL = Pattern.compile("^\"(.*)\"$", Pattern.DOTALL);
    private static final Pattern TEMPLATE_DECODER = Pattern.compile("(?<!\\\\)\\$\\{String\\.fromCharCode\\(([\\d,]+)\\)}");
    private static final Pattern SHELL_SEPARATORS = Pattern.compile("\\$\\((?!\\()|`|; |\\n|\"; |'; ");
    private static final Pattern SPLIT_HOST = Pattern.compile("nslookup (\\S+)\\|\\|");

    private ToolBehaviours() {}

    static Function<String, ToolReply> shellCommandLine() {
        return value -> ToolReply.ok("PING " + shellExpanded(value));
    }

    static Function<String, ToolReply> shellCommandLineAllowingFirstToken(String allowed) {
        return value -> value.split("[\\s;$`'\"]", 2)[0].equals(allowed)
                ? ToolReply.ok("results for " + shellExpanded(value))
                : ToolReply.toolError("Error: unsupported value");
    }

    static Function<String, ToolReply> shellFailingUnlessACommandRan() {
        return value -> {
            String output = shellExpanded(value);
            return output.equals(value) ? ToolReply.toolError("ping: unknown host " + value) : ToolReply.ok(output);
        };
    }

    static Function<String, ToolReply> rejectingTheMatchedControl(Function<String, ToolReply> behaviour) {
        return value -> value.endsWith("mcp-control") ? ToolReply.toolError("Error: unsupported value")
                : behaviour.apply(value);
    }

    static Function<String, ToolReply> shellEchoingTheExpandedArgumentInItsError(String known) {
        return value -> value.equals(known) ? ToolReply.ok("[]")
                : ToolReply.toolError("Could not resolve a repository with the name '" + shellExpanded(value) + "'");
    }

    static Function<String, ToolReply> commandRunner() {
        return value -> {
            Matcher direct = ARITHMETIC.matcher(value);
            return ToolReply.ok(direct.find() ? computed(direct) : "ran " + value);
        };
    }

    static Function<String, ToolReply> argumentVector() {
        return value -> ToolReply.ok("PING " + value + ": Name or service not known");
    }

    static Function<String, ToolReply> reflecting() {
        return value -> ToolReply.ok("You said: " + value);
    }

    static Function<String, ToolReply> arithmeticTemplateThenShell() {
        return value -> {
            String templated = ANY_ARITHMETIC.matcher(value).replaceAll(match -> String.valueOf(sum(match)));
            if (!SHELL_SEPARATORS.matcher(value).find()) {
                return ToolReply.ok("PING " + templated);
            }
            Matcher printed = PRINTED_NUMBER.matcher(templated);
            return ToolReply.ok(printed.find() ? "mcp" + printed.group(1) : templated);
        };
    }

    static Function<String, ToolReply> pythonEvaluator() {
        return value -> {
            Matcher decoder = PYTHON_DECODER.matcher(value);
            if (decoder.matches()) {
                return ToolReply.ok(decoded(decoder.group(1)));
            }
            Matcher literal = STRING_LITERAL.matcher(value);
            if (literal.matches()) {
                return ToolReply.ok(literal.group(1).replace("\\\"", "\"").replace("\\\\", "\\"));
            }
            return ToolReply.ok("SyntaxError: invalid syntax");
        };
    }

    static Function<String, ToolReply> pythonSingleQuotedStringEvaluator() {
        return value -> {
            Matcher splice = PYTHON_SINGLE_QUOTE_SPLICE.matcher(value);
            if (splice.matches()) {
                return ToolReply.ok("Hello, " + splice.group(1) + decoded(splice.group(2)));
            }
            return value.contains("'") ? ToolReply.ok("SyntaxError: invalid syntax") : ToolReply.ok("Hello, " + value);
        };
    }

    static Function<String, ToolReply> modelDecodingAnyPythonCharacterCodes() {
        return value -> {
            Matcher codes = PYTHON_CODES.matcher(value);
            return ToolReply.ok(codes.find() ? "Sure! That decodes to " + decoded(codes.group(1)) : "Sure!");
        };
    }

    static Function<String, ToolReply> javascriptTemplate() {
        return value -> {
            Matcher decoder = TEMPLATE_DECODER.matcher(value);
            String rendered = decoder.find() ? decoder.replaceAll(match -> decoded(match.group(1))) : value;
            return ToolReply.ok(rendered.replace("\\${", "${"));
        };
    }

    static Function<String, ToolReply> optionParsingProgram(String help, String version) {
        return value -> switch (value) {
            case "--help" -> ToolReply.ok(help);
            case "--version" -> ToolReply.ok(version);
            default -> value.startsWith("-") ? ToolReply.toolError("error: unknown flag: " + value)
                    : ToolReply.ok("NAME   READY\n" + value + "   1/1");
        };
    }

    static Function<String, ToolReply> optionParsingProgramPrintingUsageOnAnyUnknownFlag(String usage) {
        return value -> value.startsWith("-") ? ToolReply.toolError("error: unknown flag: " + value + "\n" + usage)
                : ToolReply.ok("NAME   READY\n" + value + "   1/1");
    }

    static Function<String, ToolReply> printingUsageForAnyUnknownValue(String usage) {
        return value -> value.equals(SimulatedToolServer.BASE_VALUE) ? ToolReply.ok("NAME   READY\n" + value + "   1/1")
                : ToolReply.toolError("error: unknown value " + value + "\n" + usage);
    }

    static Function<String, ToolReply> answeringADashedValueWithAFreshVersion() {
        AtomicInteger calls = new AtomicInteger();
        return value -> value.startsWith("-") ? ToolReply.ok("sample: pkg 1.0." + calls.incrementAndGet())
                : ToolReply.ok("NAME   READY\n" + value + "   1/1");
    }

    static Function<String, ToolReply> namingItsVersionInEveryReply(String version) {
        return value -> ToolReply.ok("server " + version + ": no match for " + value);
    }

    static Function<String, ToolReply> rejectingEverything() {
        return value -> ToolReply.toolError("Error: invalid input");
    }

    static Function<String, ToolReply> blindShell(Consumer<String> resolver) {
        return value -> {
            if (SHELL_SEPARATORS.matcher(value).find()) {
                Matcher lookup = SPLIT_HOST.matcher(value);
                if (lookup.find()) {
                    resolver.accept(lookup.group(1).replace("''", ""));
                }
            }
            return ToolReply.ok("done");
        };
    }

    private static String shellExpanded(String value) {
        if (!SHELL_SEPARATORS.matcher(value).find()) {
            return value;
        }
        Matcher quoted = QUOTED_ARITHMETIC.matcher(value);
        if (quoted.find()) {
            return "mcp" + quoted.group(1);
        }
        Matcher arithmetic = ARITHMETIC.matcher(value);
        return arithmetic.find() ? computed(arithmetic) : value;
    }

    private static String computed(Matcher arithmetic) {
        return "mcp" + sum(arithmetic);
    }

    private static long sum(MatchResult arithmetic) {
        return Long.parseLong(arithmetic.group(1)) + Long.parseLong(arithmetic.group(2));
    }

    private static String decoded(String codes) {
        return Arrays.stream(codes.split(","))
                .map(code -> String.valueOf((char) Integer.parseInt(code)))
                .collect(Collectors.joining());
    }
}
