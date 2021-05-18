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

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DtlsMessageSequenceResult extends ProbeResult {

    private TestResult startsWithInvalidMessageNumber;
    private TestResult missesMessageSequenceChecks;

    public DtlsMessageSequenceResult(TestResult startsWithInvalidMessageNumber,
        TestResult missesMessageSequenceChecks) {
        super(ProbeType.DTLS_MESSAGE_SEQUENCE);
        this.startsWithInvalidMessageNumber = startsWithInvalidMessageNumber;
        this.missesMessageSequenceChecks = missesMessageSequenceChecks;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.STARTS_WITH_INVALID_MESSAGE_SEQUENCE, startsWithInvalidMessageNumber);
        report.putResult(AnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, missesMessageSequenceChecks);
    }

}
