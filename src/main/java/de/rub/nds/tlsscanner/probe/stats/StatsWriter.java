/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.stats;

import de.rub.nds.tlsattacker.core.state.State;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author robert
 */
public class StatsWriter {

    private final List<StatExtractor> extractorList;

    public StatsWriter() {
        extractorList = new LinkedList<>();
        extractorList.add(new RandomExtractor());
        extractorList.add(new DhModulusExtractor());
        extractorList.add(new DhPublicKeyExtractor());
        extractorList.add(new EcPublicKeyExtracot());
    }

    public void extract(State state) {
        for (StatExtractor extractor : extractorList) {
            extractor.extract(state);
        }
    }

    public List<ExtractedValueContainer> getCumulatedExtractedValues() {
        List<ExtractedValueContainer> containerList = new LinkedList<>();
        for (StatExtractor extractor : extractorList) {
            containerList.add(extractor.getContainer());
        }
        return containerList;
    }
}
