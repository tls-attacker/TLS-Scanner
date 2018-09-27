package de.rub.nds.tlsscanner.probe.stats;

import de.rub.nds.tlsattacker.core.state.State;

public abstract class StatExtractor {

    public abstract void extract(State state);

    public abstract ExtractedValueContainer getContainerList();

    private final TrackableValueType valueType;

    public StatExtractor(TrackableValueType valueType) {
        this.valueType = valueType;
    }

    public TrackableValueType getValueType() {
        return valueType;
    }
}
