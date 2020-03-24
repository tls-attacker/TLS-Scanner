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

public class DrownResult extends ProbeResult {

    private final TestResult generalDrown;

    private final TestResult extraClear;

    public DrownResult(TestResult generalDrown, TestResult extraClear) {
        super(ProbeType.DROWN);
        this.generalDrown = generalDrown;
        this.extraClear = extraClear;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.VULNERABLE_TO_EXTRA_CLEAR_DROWN, extraClear);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN, generalDrown);
    }

}
