package com.mcpscanner.scan;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PathArgumentHeuristicTest {

    @Test
    void matchesArgumentNameContainingPath() {
        assertThat(PathArgumentHeuristic.isPathLike("path", null)).isTrue();
        assertThat(PathArgumentHeuristic.isPathLike("filepath", null)).isTrue();
        assertThat(PathArgumentHeuristic.isPathLike("workspace_path", null)).isTrue();
    }

    @Test
    void matchesArgumentNameContainingFileOrDir() {
        assertThat(PathArgumentHeuristic.isPathLike("file", null)).isTrue();
        assertThat(PathArgumentHeuristic.isPathLike("filename", null)).isTrue();
        assertThat(PathArgumentHeuristic.isPathLike("directory", null)).isTrue();
        assertThat(PathArgumentHeuristic.isPathLike("folder", null)).isTrue();
    }

    @Test
    void matchesCaseInsensitive() {
        assertThat(PathArgumentHeuristic.isPathLike("FilePath", null)).isTrue();
        assertThat(PathArgumentHeuristic.isPathLike("DOCUMENT", null)).isTrue();
    }

    @Test
    void matchesWhenOnlyDescriptionHints() {
        assertThat(PathArgumentHeuristic.isPathLike("target", "The thing to read from disk")).isTrue();
        assertThat(PathArgumentHeuristic.isPathLike("input", "Filesystem path to open")).isTrue();
        assertThat(PathArgumentHeuristic.isPathLike("blob", "Download the asset")).isTrue();
    }

    @Test
    void returnsFalseForUnrelatedNames() {
        assertThat(PathArgumentHeuristic.isPathLike("count", null)).isFalse();
        assertThat(PathArgumentHeuristic.isPathLike("name", null)).isFalse();
        assertThat(PathArgumentHeuristic.isPathLike("username", null)).isFalse();
        assertThat(PathArgumentHeuristic.isPathLike("query", "The SQL query to execute")).isFalse();
    }

    @Test
    void returnsFalseForNullName() {
        assertThat(PathArgumentHeuristic.isPathLike(null, null)).isFalse();
    }

    @Test
    void returnsFalseForEmptyName() {
        assertThat(PathArgumentHeuristic.isPathLike("", "")).isFalse();
    }

    @Test
    void matchesAttachmentAndArchiveAndDownloadPath() {
        assertThat(PathArgumentHeuristic.isPathLike("attachment", null)).isTrue();
        assertThat(PathArgumentHeuristic.isPathLike("archive", null)).isTrue();
        assertThat(PathArgumentHeuristic.isPathLike("download_path", null)).isTrue();
    }

    @Test
    void matchesPathLikeWhenNameNullButDescriptionHints() {
        assertThat(PathArgumentHeuristic.isPathLike(null, "Path to the report")).isTrue();
    }

    @Test
    void doesNotMatchWhenBothNullAndDescriptionEmpty() {
        assertThat(PathArgumentHeuristic.isPathLike(null, "")).isFalse();
        assertThat(PathArgumentHeuristic.isPathLike("", null)).isFalse();
    }
}
