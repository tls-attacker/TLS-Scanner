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
public class DtlsFragmentationResult extends ProbeResult {

    private TestResult messageSequenceChecks;
    private TestResult sequenceNumberChecks;

    public DtlsFragmentationResult(TestResult messageSequenceChecks, TestResult sequenceNumberChecks) {
        super(ProbeType.DTLS_FRAGMENTATION);
        this.messageSequenceChecks = messageSequenceChecks;
        this.sequenceNumberChecks = sequenceNumberChecks;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, messageSequenceChecks);
        report.putResult(AnalyzedProperty.MISSES_SEQUENCE_NUMBER_CHECKS, sequenceNumberChecks);
    }

}
