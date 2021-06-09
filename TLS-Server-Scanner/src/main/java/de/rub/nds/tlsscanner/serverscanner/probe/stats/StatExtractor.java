/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.stats;

import de.rub.nds.tlsattacker.core.state.State;

public abstract class StatExtractor<T> {

    private final ExtractedValueContainer<T> container;
    private final TrackableValueType valueType;

    public StatExtractor(TrackableValueType valueType) {
        this.valueType = valueType;
        container = new ExtractedValueContainer<>(valueType);
    }

    public TrackableValueType getValueType() {
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
