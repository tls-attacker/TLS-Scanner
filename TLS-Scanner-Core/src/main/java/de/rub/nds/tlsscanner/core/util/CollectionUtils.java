/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.util;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class CollectionUtils {

    public static <E> Set<E> mergeCollectionsIntoSet(Collection<E>... collections) {
        Set<E> mergeResult = new HashSet<>();
        for (Collection<E> currentCollection : collections) {
            if (currentCollection == null) {
                continue;
            }

            mergeResult.addAll(currentCollection);
        }
        return mergeResult;
    }
}
