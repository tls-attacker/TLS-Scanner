package de.rub.nds.tlsscanner.clientscanner.util.helper;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;

import org.apache.commons.lang3.tuple.Pair;

public class SingleMapQ<K, V> {
    private Map<K, Queue<V>> mapQ = new HashMap<>();

    public void enqueue(K k, V v) {
        Queue<V> q;
        synchronized (mapQ) {
            q = mapQ.get(k);
            if (q == null) {
                q = new LinkedList<>();
                mapQ.put(k, q);
            }
            // adding the element is still synced, as we do not want q to possibly be
            // removed from mapQ
            q.add(v);
        }
    }

    public V dequeue(K k) {
        V ret;
        Queue<V> q;
        q = mapQ.get(k);
        if (q == null) {
            return null;
        }
        ret = q.remove();
        synchronized (mapQ) {
            if (q.isEmpty()) {
                mapQ.remove(k);
            }
        }
        return ret;
    }

    public Pair<K, V> dequeueAny() {
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
