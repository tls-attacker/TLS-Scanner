package de.rub.nds.tlsscanner.probe.stats;

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
