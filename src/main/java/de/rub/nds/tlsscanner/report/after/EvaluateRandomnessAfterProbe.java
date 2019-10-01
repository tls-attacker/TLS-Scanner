/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.statistics.RandomEvaluationResult;
import java.util.List;

public class EvaluateRandomnessAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        List<ExtractedValueContainer> extractedValueContainerList = report.getExtractedValueContainerList();
        RandomEvaluationResult result = RandomEvaluationResult.NOT_ANALYZED;
        for (ExtractedValueContainer container : extractedValueContainerList) {
            if (container.getType() == TrackableValueType.RANDOM) {
                if (!container.areAllValuesDiffernt()) {
                    result = RandomEvaluationResult.DUPLICATES;
                }
                boolean allUnixTime = true;
                for (Object o : container.getExtractedValueList()) {
                    ComparableByteArray byteArray = (ComparableByteArray) o;

                }
                result = RandomEvaluationResult.NO_DUPLICATES;
            }

        }
        report.setRandomEvaluationResult(result);
    }

}
