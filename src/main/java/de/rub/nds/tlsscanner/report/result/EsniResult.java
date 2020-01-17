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

public class EsniResult  extends ProbeResult {
    private TestResult receivedCorrectNonce;

    public EsniResult(TestResult receivedCorrectNonce) {
        super(ProbeType.ESNI);
        this.receivedCorrectNonce = receivedCorrectNonce;
    }

    @Override
    public void mergeData(SiteReport report) {
    	report.putResult(AnalyzedProperty.SUPPORTS_ESNI, receivedCorrectNonce);
    }	
}
