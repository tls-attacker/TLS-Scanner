/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/*
 */

package de.rub.nds.tlsscanner.serverscanner.probe.mac;

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
