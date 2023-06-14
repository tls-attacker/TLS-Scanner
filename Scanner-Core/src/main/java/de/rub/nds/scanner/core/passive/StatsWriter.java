/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.passive;

import de.rub.nds.tlsattacker.core.state.State;
import java.util.LinkedList;
import java.util.List;

public class StatsWriter {

    private final List<StatExtractor> extractorList;

    private int stateCounter = 0;

    public StatsWriter() {
        extractorList = new LinkedList<>();
    }

    public void addExtractor(StatExtractor extractor) {
        extractorList.add(extractor);
    }

    public void extract(State state) {
        for (StatExtractor extractor : extractorList) {
            extractor.extract(state);
        }
        stateCounter++;
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
