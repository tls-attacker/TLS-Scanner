/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

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
