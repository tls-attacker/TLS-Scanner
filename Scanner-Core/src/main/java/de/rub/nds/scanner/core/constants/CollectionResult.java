/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.constants;

import java.util.Collection;

/**
 * Represents {@link TestResult}s of type {@link Collection} with objects of type T.
 *
 * @param <T> the type of which the CollectionResult consists.
 */
public class CollectionResult<T> implements TestResult {

    private final String name;
    protected final Collection<T> collection;

    /**
     * The constructor for the CollectionResult. Use property.name() for the name parameter.
     *
     * @param collection The result collection.
     * @param name The name of the CollectionResult object.
     */
    public CollectionResult(Collection<T> collection, String name) {
        this.collection = collection;
        this.name = name;
    }

    /**
     * @return the collection of the CollectionResult object of type T.
     */
    public Collection<T> getCollection() {
        return collection;
    }

    @Override
    public String name() {
        return name;
    }
}
