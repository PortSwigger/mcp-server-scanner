package com.mcpscanner.config;

import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

record TypedLayers<T>(Layer<T> project, Layer<T> user) {

    record Layer<T>(Function<String, T> read, BiConsumer<String, T> write, Consumer<String> delete,
                    Supplier<Set<String>> keys) {

        Set<String> userDefaultKeys() {
            return keys.get().stream().filter(SettingKey::allowsUserDefault).collect(Collectors.toSet());
        }
    }

    boolean projectIsEmpty() {
        return project.keys().get().isEmpty();
    }

    void copyUserValuesToProject() {
        for (String key : user.userDefaultKeys()) {
            T value = user.read().apply(key);
            if (SettingKey.allowsUserDefault(key, value)) {
                project.write().accept(key, value);
            }
        }
    }

    void copyProjectValuesToUser() {
        for (String key : project.userDefaultKeys()) {
            T value = project.read().apply(key);
            if (SettingKey.allowsUserDefault(key, value)) {
                user.write().accept(key, value);
            } else {
                user.delete().accept(key);
            }
        }
    }

    void clearUser() {
        Set.copyOf(user.keys().get()).forEach(user.delete());
    }
}
