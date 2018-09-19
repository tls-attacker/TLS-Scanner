/*
 */
package de.rub.nds.tlsscanner.probe.mac;

import de.rub.nds.tlsattacker.core.state.State;

/**
 *
 * @author robert
 */
public class StateIndexPair {

    private int index;

    private State state;

    public StateIndexPair(int index, State state) {
        this.index = index;
        this.state = state;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }
}
