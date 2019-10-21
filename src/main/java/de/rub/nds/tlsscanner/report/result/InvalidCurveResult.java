/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class InvalidCurveResult extends ProbeResult {

    private final TestResult vulnerableClassic;
    private final TestResult vulnerableEphemeral;
    private final TestResult vulnerableTwist;

    public InvalidCurveResult(TestResult vulnerableClassic, TestResult vulnerableEphemeral, TestResult vulnerableTwist) {
        super(ProbeType.INVALID_CURVE);
        this.vulnerableClassic = vulnerableClassic;
        this.vulnerableEphemeral = vulnerableEphemeral;
        this.vulnerableTwist = vulnerableTwist;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE, vulnerableClassic);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL, vulnerableEphemeral);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST, vulnerableTwist);
    }

}
