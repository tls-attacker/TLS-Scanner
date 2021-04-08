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
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author robert
 */
public class StatsWriter {

    private final List<StatExtractor> extractorList;

    private int stateCounter = 0;

    public StatsWriter() {
        extractorList = new LinkedList<>();
        extractorList.add(new RandomExtractor());
        extractorList.add(new DhPublicKeyExtractor());
        extractorList.add(new EcPublicKeyExtractor());
    }

    public void extract(State state) {
        for (StatExtractor extractor : extractorList) {
            extractor.extract(state);
            stateCounter++;
        }
    }

    public List<ExtractedValueContainer> getCumulatedExtractedValues() {
        List<ExtractedValueContainer> containerList = new LinkedList<>();
        for (StatExtractor extractor : extractorList) {
            containerList.add(extractor.getContainer());
        }
        return containerList;
    }

    public int getStateCounter() {
        return stateCounter;
    }

}
