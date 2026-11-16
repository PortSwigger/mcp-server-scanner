package com.mcpscanner.identity;

import com.mcpscanner.auth.AuthStrategy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.UnaryOperator;

public final class IdentityRegistry {

    private static final String COPY_SUFFIX = " copy";

    private final IdentityStore store;
    private final List<Identity> identities;
    private final Map<String, AuthStrategy> credentials = new HashMap<>();
    private final Map<String, IdentityAuthKind> detected = new HashMap<>();
    private final Listeners listeners = new Listeners();
    private String primaryId;

    public IdentityRegistry(IdentityStore store) {
        this.store = store;
        StoredIdentities loaded = store.load();
        StoredIdentities withPrimary = PrimaryUserMigration.ensurePrimary(loaded, store::legacyPrimary);
        StoredIdentities detecting = store.detectMigrationPending()
                ? DetectAutomaticallyMigration.apply(withPrimary, store.legacyAutoDetect()) : withPrimary;
        StoredIdentities stored = store.migrateOAuthGrant(detecting);
        this.identities = new ArrayList<>(stored.identities());
        this.primaryId = stored.primaryId().orElseThrow();
        if (stored != loaded) {
            persist();
            store.clearLegacyPrimary();
        }
        store.markDetectMigrated();
        store.retireOAuthGrant();
    }

    public synchronized List<Identity> identities() {
        return List.copyOf(identities);
    }

    public synchronized Identity primaryUser() {
        return require(primaryId);
    }

    public synchronized boolean isPrimary(String id) {
        return primaryId.equals(id);
    }

    public void makePrimary(String id) {
        synchronized (this) {
            requireKnown(id);
            if (primaryId.equals(id)) {
                return;
            }
            demotePrimaryOnlyKind();
            primaryId = id;
            persist();
        }
        fireChanged();
    }

    public synchronized Optional<Identity> find(String id) {
        return identities.stream().filter(identity -> identity.id().equals(id)).findFirst();
    }

    public synchronized Identity require(String id) {
        return identities.get(indexOf(id));
    }

    public Identity add(Identity identity) {
        Identity added = comparable(identity);
        synchronized (this) {
            requireAvailableName(added.name(), null);
            identities.add(added);
            persist();
        }
        fireChanged();
        return added;
    }

    public void update(Identity identity) {
        synchronized (this) {
            int index = indexOf(identity.id());
            requireAvailableName(identity.name(), identity.id());
            if (identities.get(index).authKind() != identity.authKind()) {
                detected.remove(identity.id());
            }
            identities.set(index, identity);
            persist();
        }
        fireChanged();
    }

    void modify(String id, UnaryOperator<Identity> change) {
        synchronized (this) {
            int index = indexOf(id);
            identities.set(index, change.apply(identities.get(index)));
            persist();
        }
        fireChanged();
    }

    void modifyAll(UnaryOperator<Identity> change) {
        synchronized (this) {
            identities.replaceAll(change);
            persist();
        }
        fireChanged();
    }

    public void remove(String id) {
        synchronized (this) {
            int index = indexOf(id);
            if (primaryId.equals(id)) {
                throw new IllegalStateException("Make another user primary before removing "
                        + identities.get(index).name());
            }
            identities.remove(index);
            credentials.remove(id);
            detected.remove(id);
            persist();
        }
        fireChanged();
    }

    public Identity duplicate(String id) {
        Identity copy;
        synchronized (this) {
            Identity original = require(id);
            copy = comparable(original.copyNamed(unusedCopyName(original.name())));
            identities.add(copy);
            persist();
        }
        fireChanged();
        return copy;
    }

    public void setCredential(String id, AuthStrategy credential) {
        synchronized (this) {
            requireKnown(id);
            credentials.put(id, credential);
        }
        fireChanged();
    }

    public void removeCredential(String id) {
        boolean removed;
        synchronized (this) {
            removed = credentials.remove(id) != null;
            detected.remove(id);
        }
        if (removed) {
            fireChanged();
        }
    }

    public synchronized Optional<AuthStrategy> credential(String id) {
        return Optional.ofNullable(credentials.get(id));
    }

    public synchronized boolean hasAnyCredential() {
        return !credentials.isEmpty();
    }

    public void recordDetected(String id, IdentityAuthKind outcome) {
        synchronized (this) {
            requireKnown(id);
            detected.put(id, outcome);
        }
        fireChanged();
    }

    public synchronized Optional<IdentityAuthKind> detected(String id) {
        return Optional.ofNullable(detected.get(id));
    }

    public List<Identity> clearCredentials() {
        List<Identity> holders;
        synchronized (this) {
            holders = identities.stream().filter(identity -> credentials.containsKey(identity.id())).toList();
            credentials.clear();
            detected.clear();
        }
        fireChanged();
        return holders;
    }

    public synchronized List<Identity> otherUsers() {
        return identities.stream().filter(identity -> !primaryId.equals(identity.id())).toList();
    }

    public synchronized int otherUserCount() {
        return otherUsers().size();
    }

    public synchronized List<Identity> compared() {
        return otherUsers().stream()
                .filter(Identity::compared)
                .filter(identity -> credentials.containsKey(identity.id()))
                .toList();
    }

    public void addListener(Runnable listener) {
        listeners.add(listener);
    }

    public void removeListener(Runnable listener) {
        listeners.remove(listener);
    }

    private void demotePrimaryOnlyKind() {
        int index = indexOf(primaryId);
        Identity previous = identities.get(index);
        if (!previous.authKind().offeredToComparedUsers()) {
            identities.set(index, comparable(previous));
            credentials.remove(primaryId);
            detected.remove(primaryId);
        }
    }

    private static Identity comparable(Identity identity) {
        return identity.authKind().offeredToComparedUsers() ? identity : identity.withAuthKind(IdentityAuthKind.NONE);
    }

    private void requireKnown(String id) {
        indexOf(id);
    }

    private int indexOf(String id) {
        for (int i = 0; i < identities.size(); i++) {
            if (identities.get(i).id().equals(id)) {
                return i;
            }
        }
        throw new IllegalArgumentException("Unknown identity: " + id);
    }

    private void requireAvailableName(String name, String ownId) {
        if (name.isBlank()) {
            throw new IllegalArgumentException("Identity name must not be blank");
        }
        if (nameTaken(name, ownId)) {
            throw new IllegalArgumentException("An identity named \"" + name.strip() + "\" already exists");
        }
    }

    private boolean nameTaken(String name, String ownId) {
        return IdentityNames.of(identities.stream().filter(identity -> !identity.id().equals(ownId)).toList())
                .isTaken(name);
    }

    private String unusedCopyName(String name) {
        return IdentityNames.of(identities).unused(name + COPY_SUFFIX);
    }

    private void persist() {
        store.save(StoredIdentities.of(identities, primaryId));
    }

    private void fireChanged() {
        listeners.fire();
    }
}
