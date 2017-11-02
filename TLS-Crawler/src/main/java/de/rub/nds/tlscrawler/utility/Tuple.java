/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.utility;

/**
 * Simple tuple implementation for convenience.
 *
 * @param <T1> Type of the first object.
 * @param <T2> Type of the second object.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class Tuple<T1, T2> {
    private final T1 first;
    private final T2 second;

    public Tuple(T1 first, T2 second) {
        this.first = first;
        this.second = second;
    }

    public T1 getFirst() {
        return this.first;
    }

    public T2 getSecond() {
        return this.second;
    }

    /**
     * Convenience factory method.
     *
     * @param first First object.
     * @param second Second object.
     * @param <A> Type of first object, can be inferred.
     * @param <B> Type of second object, can be inferred.
     * @return The tuple (first, second).
     */
    public static <A, B> Tuple<A, B> create(A first, B second) {
        return new Tuple<A, B>(first, second);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Tuple)) {
            return false;
        }

        Tuple<?, ?> p = (Tuple<?, ?>) o;

        return equal(p.first, this.first) && equal(p.second, this.second);
    }

    @Override
    public int hashCode() {
        return (this.first == null ? 0 : this.first.hashCode())
                ^ (this.second == null ? 0 : this.second.hashCode());
    }

    private static boolean equal(Object a, Object b) {
        return a == b || (a != null && a.equals(b));
    }
}
