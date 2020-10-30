/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.util.helper;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;

import org.apache.commons.lang3.tuple.Pair;

public class SingleMapQ<K, V> {
    private final Map<K, Queue<V>> mapQ = new HashMap<>();

    public synchronized void enqueue(K k, V v) {
        Queue<V> q = mapQ.computeIfAbsent(k, _k -> new LinkedList<>());
        q.add(v);
    }

    public synchronized V dequeue(K k) {
        Queue<V> q = mapQ.get(k);
        if (q == null) {
            return null;
        }
        V ret = q.remove();
        if (q.isEmpty()) {
            mapQ.remove(k);
        }
        return ret;
    }

    public synchronized Pair<K, V> dequeueAny() {
        for (K k : mapQ.keySet()) {
            V v = dequeue(k);
            if (v != null) {
                return Pair.of(k, v);
            }
        }
        return null;
    }

    public boolean isEmpty() {
        return mapQ.isEmpty();
    }
}
