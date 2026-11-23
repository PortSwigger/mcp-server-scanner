package com.mcpscanner.config;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Preferences;

import java.util.List;
import java.util.Set;

final class LayeredSettings {

    private final PersistedObject project;
    private final TypedLayers<String> strings;
    private final TypedLayers<Boolean> booleans;
    private final TypedLayers<Integer> integers;
    private final TypedLayers<Long> longs;

    LayeredSettings(PersistedObject project, Preferences user) {
        this.project = project;
        this.strings = new TypedLayers<>(
                new TypedLayers.Layer<>(project::getString, project::setString, project::deleteString,
                        project::stringKeys),
                new TypedLayers.Layer<>(user::getString, user::setString, user::deleteString, user::stringKeys));
        this.booleans = new TypedLayers<>(
                new TypedLayers.Layer<>(project::getBoolean, project::setBoolean, project::deleteBoolean,
                        project::booleanKeys),
                new TypedLayers.Layer<>(user::getBoolean, user::setBoolean, user::deleteBoolean, user::booleanKeys));
        this.integers = new TypedLayers<>(
                new TypedLayers.Layer<>(project::getInteger, project::setInteger, project::deleteInteger,
                        project::integerKeys),
                new TypedLayers.Layer<>(user::getInteger, user::setInteger, user::deleteInteger, user::integerKeys));
        this.longs = new TypedLayers<>(
                new TypedLayers.Layer<>(project::getLong, project::setLong, project::deleteLong, project::longKeys),
                new TypedLayers.Layer<>(user::getLong, user::setLong, user::deleteLong, user::longKeys));
    }

    String getString(String key) {
        return project.getString(key);
    }

    void setString(String key, String value) {
        project.setString(key, value);
    }

    void deleteString(String key) {
        project.deleteString(key);
    }

    Set<String> projectStringKeys() {
        return project.stringKeys();
    }

    Boolean getBoolean(String key) {
        return project.getBoolean(key);
    }

    void setBoolean(String key, boolean value) {
        project.setBoolean(key, value);
    }

    void deleteBoolean(String key) {
        project.deleteBoolean(key);
    }

    Set<String> projectBooleanKeys() {
        return project.booleanKeys();
    }

    Integer getInteger(String key) {
        return project.getInteger(key);
    }

    void setInteger(String key, int value) {
        project.setInteger(key, value);
    }

    Long getLong(String key) {
        return project.getLong(key);
    }

    void setLong(String key, long value) {
        project.setLong(key, value);
    }

    void deleteLong(String key) {
        project.deleteLong(key);
    }

    void startNewProjectFromUserDefaults() {
        if (allTypes().stream().allMatch(TypedLayers::projectIsEmpty)) {
            allTypes().forEach(TypedLayers::copyUserValuesToProject);
            project.setBoolean(SettingKey.SEEDED_FROM_USER_DEFAULTS.key(), true);
        }
    }

    void saveProjectValuesAsUserDefaults() {
        allTypes().forEach(TypedLayers::copyProjectValuesToUser);
    }

    void clearUserDefaults() {
        allTypes().forEach(TypedLayers::clearUser);
    }

    private List<TypedLayers<?>> allTypes() {
        return List.of(strings, booleans, integers, longs);
    }
}
