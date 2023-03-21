/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.passive;

import de.rub.nds.tlsattacker.core.state.State;

public abstract class StatExtractor<T> {

    private final ExtractedValueContainer<T> container;
    private final TrackableValue valueType;

    public StatExtractor(TrackableValue valueType) {
        this.valueType = valueType;
        container = new ExtractedValueContainer<>(valueType);
    }

    public TrackableValue getValueType() {
        return valueType;
    }

    public void put(T t) {
        container.put(t);
    }

    public ExtractedValueContainer<T> getContainer() {
        return container;
    }

    public abstract void extract(State state);
}
