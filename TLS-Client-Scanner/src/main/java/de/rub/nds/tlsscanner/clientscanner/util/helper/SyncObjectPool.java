/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.util.helper;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class SyncObjectPool {
    private final Lock lock = new ReentrantLock();
    private final Condition keyCondition = lock.newCondition();
    private final Set<String> lockedKeys = new HashSet<>();

    @SuppressWarnings("squid:S2093")
    // returning an AutoCloseable from within the try triggers that we should
    // use a try with resources instead
    public SyncObject get(String key) {
        lock.lock();
        try {
            while (lockedKeys.contains(key)) {
                keyCondition.await();
            }
            lockedKeys.add(key);
            return new SyncObject(key);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } finally {
            lock.unlock();
        }
    }

    public class SyncObject implements AutoCloseable {
        private final String key;

        public SyncObject(String key) {
            this.key = key;
        }

        @Override
        public void close() {
            lockedKeys.remove(key);
            lock.lock();
            try {
                keyCondition.signal();
            } finally {
                lock.unlock();
            }
        }
    }
}
