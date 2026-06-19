package com.mcpscanner.scan;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CodeArgumentHeuristicTest {

    @Test
    void matchesArgumentNameContainingCodeOrScript() {
        assertThat(CodeArgumentHeuristic.isCodeLike("code", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("source_code", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("script", null)).isTrue();
    }

    @Test
    void matchesArgumentNameContainingExpressionOrFormatOrTemplate() {
        assertThat(CodeArgumentHeuristic.isCodeLike("expression", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("expr", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("format", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("template", null)).isTrue();
    }

    @Test
    void matchesArgumentNameContainingCmdOrCommandOrShell() {
        assertThat(CodeArgumentHeuristic.isCodeLike("cmd", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("command", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("shell", null)).isTrue();
    }

    @Test
    void matchesArgumentNameContainingLanguageTokens() {
        assertThat(CodeArgumentHeuristic.isCodeLike("js", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("python", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("program", null)).isTrue();
    }

    @Test
    void matchesCaseInsensitive() {
        assertThat(CodeArgumentHeuristic.isCodeLike("UserScript", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("PYTHON_EXPR", null)).isTrue();
    }

    @Test
    void matchesWhenOnlyDescriptionHints() {
        assertThat(CodeArgumentHeuristic.isCodeLike("input", "JavaScript code to evaluate")).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("payload", "Shell command to execute")).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("body", "Expression to run on the server")).isTrue();
    }

    @Test
    void returnsFalseForUnrelatedNames() {
        assertThat(CodeArgumentHeuristic.isCodeLike("count", null)).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("username", "The user's login name")).isFalse();
    }

    @Test
    void matchesShellInjectionProneArgumentNames() {
        // Real-world command-injection MCP CVEs almost never name the vulnerable arg
        // `code`/`command`/`script` — they are innocuous-looking strings that get
        // interpolated into a shell command. The headless RCE validation against
        // @cyanheads/git-mcp-server (CVE-2025-53107) showed `initialBranch`,
        // `branchName`, and `path`/`targetPath` are the live sinks, and
        // mcp-package-docs (CVE-2025-54073) injects via `package`. Because the RCE
        // check only probes user-SELECTED tools and only fires on a confirmed OOB
        // callback, flagging these costs at most a few no-callback HTTP probes — a
        // missed sink, by contrast, is a silent false negative on a real RCE.
        // Matching is token-aware: the name is split on camelCase/underscore/hyphen
        // boundaries and a token must EQUAL a hint, so `branchName` -> [branch, name]
        // matches on the `branch` token.
        assertThat(CodeArgumentHeuristic.isCodeLike("initialBranch", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("branchName", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("targetPath", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("path", "Filesystem path to read")).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("package", "Full package import path")).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("repository", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("repositoryUrl", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("callbackUrl", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("url", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("directory", null)).isTrue();
    }

    @Test
    void matchesAllLowercaseCompoundSinkNames() {
        // FN fix (Codex review): all-lowercase compounds with no camelCase/underscore boundary
        // (filepath, filename, branchname, targetpath) never split into a hint token, so whole-token
        // matching missed them. A constrained boundary check on the high-signal sink stems
        // path/file/branch catches them — these are the live filesystem/command-injection sinks.
        assertThat(CodeArgumentHeuristic.isCodeLike("filepath", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("filename", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("branchname", null)).isTrue();
        assertThat(CodeArgumentHeuristic.isCodeLike("targetpath", null)).isTrue();
    }

    @Test
    void lowercaseCompoundStemCheckStillRejectsFalseFriends() {
        // The constrained stem check must NOT re-open the substring collisions that whole-token
        // matching closed. `file` is matched only as a PREFIX so `profile` (file as a suffix) stays
        // out; path/branch are not substrings of any of these either.
        assertThat(CodeArgumentHeuristic.isCodeLike("profile", null)).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("redirect", null)).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("redirectUri", null)).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("report", null)).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("reportId", null)).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("stage", null)).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("username", null)).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("referrer", null)).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("count", null)).isFalse();
    }

    @Test
    void doesNotMatchHintSubstringsInsideUnrelatedTokens() {
        // The broadened vocabulary used to match by naive substring, so short hints
        // collided with unrelated words: `file` in profile, `dir` in redirect, `repo`
        // in report, `tag` in stage, `user`/`name` in username. Token-aware matching
        // splits the name and requires a whole-token equality, so these no longer fire
        // spurious RCE probes.
        assertThat(CodeArgumentHeuristic.isCodeLike("profile", null)).isFalse();      // not "file"
        assertThat(CodeArgumentHeuristic.isCodeLike("redirect", null)).isFalse();     // not "dir"
        assertThat(CodeArgumentHeuristic.isCodeLike("redirectUri", null)).isFalse();  // [redirect, uri]
        assertThat(CodeArgumentHeuristic.isCodeLike("report", null)).isFalse();       // not "repo"
        assertThat(CodeArgumentHeuristic.isCodeLike("reportId", null)).isFalse();     // [report, id]
        assertThat(CodeArgumentHeuristic.isCodeLike("stage", null)).isFalse();        // not "tag"
        assertThat(CodeArgumentHeuristic.isCodeLike("username", null)).isFalse();     // [user, name]
        assertThat(CodeArgumentHeuristic.isCodeLike("referrer", null)).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("count", null)).isFalse();
    }

    @Test
    void returnsFalseForNullOrEmptyInput() {
        assertThat(CodeArgumentHeuristic.isCodeLike(null, null)).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("", "")).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike(null, "")).isFalse();
        assertThat(CodeArgumentHeuristic.isCodeLike("", null)).isFalse();
    }

    @Test
    void matchesQueryAsCodeLikeArgumentName() {
        assertThat(CodeArgumentHeuristic.isCodeLike("query", null)).isTrue();
    }

    @Test
    void matchesUserQueryEvenThoughItIsNotCodeLike() {
        // The heuristic is intentionally noisy on the discovery side because the RCE
        // check requires an out-of-band Collaborator interaction to actually fire — any
        // false-positive code-arg classification gets filtered by the no-callback signal.
        // So matching a SQL/search arg like `user_query` here costs only a few HTTP probes,
        // not a false-positive issue.
        assertThat(CodeArgumentHeuristic.isCodeLike("user_query", "filter results")).isTrue();
    }
}
