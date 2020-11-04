/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.statistics.CookieEvaluationResult;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class EvaluateCookieAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {

        if (report.getExtractedValueContainerMap().isEmpty()) {
            report.setCookieEvaluationResult(CookieEvaluationResult.NOT_ANALYZED);
            return;
        }

        ExtractedValueContainer container = report.getExtractedValueContainerMap().get(TrackableValueType.COOKIE);
        CookieEvaluationResult result = CookieEvaluationResult.NOT_ANALYZED;
        if (!container.areAllValuesDiffernt()) {
            result = CookieEvaluationResult.DUPLICATES;
        } else {
            result = CookieEvaluationResult.NO_DUPLICATES;
        }
        report.setCookieEvaluationResult(result);
    }

}
