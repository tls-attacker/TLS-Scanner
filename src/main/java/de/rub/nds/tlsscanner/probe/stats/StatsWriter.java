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
