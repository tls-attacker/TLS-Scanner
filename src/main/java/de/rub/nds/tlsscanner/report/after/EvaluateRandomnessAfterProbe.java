/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.statistics.RandomEvaluationResult;

public class EvaluateRandomnessAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        ExtractedValueContainer container = report.getExtractedValueContainerMap().get(TrackableValueType.RANDOM);
        RandomEvaluationResult result = RandomEvaluationResult.NOT_ANALYZED;
        if (!container.areAllValuesDiffernt()) {
            result = RandomEvaluationResult.DUPLICATES;
        } else {
            result = RandomEvaluationResult.NO_DUPLICATES;
        }
        report.setRandomEvaluationResult(result);
    }

}
