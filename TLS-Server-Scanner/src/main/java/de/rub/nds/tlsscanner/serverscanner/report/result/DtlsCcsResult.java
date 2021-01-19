/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DtlsCcsResult extends ProbeResult {

    private TestResult isEarlyFinished;
    private TestResult isAcceptMultipleCCS;
    private TestResult isAcceptUnencryptedAppData;

    public DtlsCcsResult(TestResult isAcceptUnencryptedAppData, TestResult isEarlyFinished,
            TestResult isAcceptMultipleCCS) {
        super(ProbeType.DTLS_CCS);
        this.isAcceptUnencryptedAppData = isAcceptUnencryptedAppData;
        this.isEarlyFinished = isEarlyFinished;
        this.isAcceptMultipleCCS = isAcceptMultipleCCS;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.ACCEPT_UNENCRYPTED_APP_DATA, isAcceptUnencryptedAppData);
        report.putResult(AnalyzedProperty.HAS_EARLY_FINISHED_BUG, isEarlyFinished);
        report.putResult(AnalyzedProperty.HAS_MULTIPLE_CSS_BUG, isAcceptMultipleCCS);
    }

}
