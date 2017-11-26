/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.utility;

/**
 * Simple two-tuple interface.
 *
 * @param <T1> Type of the first object.
 * @param <T2> Type of the second object.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface ITuple<T1, T2> {

    /**
     * @return The first element of the tuple.
     */
    T1 getFirst();

    /**
     * @return The second element of the tuple.
     */
    T2 getSecond();
}