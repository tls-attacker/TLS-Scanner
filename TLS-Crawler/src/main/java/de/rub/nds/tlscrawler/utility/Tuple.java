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
    public final T1 a;
    public final T2 b;

    public Tuple(T1 a, T2 b) {
        this.a = a;
        this.b = b;
    }

    /**
     * Convenience factory method.
     *
     * @param a First object.
     * @param b Second object.
     * @param <A> Type of first object, can be inferred.
     * @param <B> Type of second object, can be inferred.
     * @return The tuple (a, b).
     */
    public static <A, B> Tuple<A, B> create(A a, B b) {
        return new Tuple<A, B>(a, b);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Tuple)) {
            return false;
        }

        Tuple<?, ?> p = (Tuple<?, ?>) o;

        return equal(p.a, this.a) && equal(p.b, this.b);
    }

    @Override
    public int hashCode() {
        return (this.a == null ? 0 : this.a.hashCode())
                ^ (this.b == null ? 0 : this.b.hashCode());
    }

    private static boolean equal(Object a, Object b) {
        return a == b || (a != null && a.equals(b));
    }
}
