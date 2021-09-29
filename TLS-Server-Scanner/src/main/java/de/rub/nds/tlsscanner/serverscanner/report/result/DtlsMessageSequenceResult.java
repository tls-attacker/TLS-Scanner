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
    private TestResult skippsMessageNumbersOnce;
    private TestResult skippsMessageNumbersMultiple;
    private TestResult acceptsRandomMessageNumbers;

    public DtlsMessageSequenceResult(TestResult startsWithInvalidMessageNumber, TestResult skippsMessageNumbersOnce,
        TestResult skippsMessageNumbersMultiple, TestResult acceptsRandomMessageNumbers) {
        super(ProbeType.DTLS_MESSAGE_SEQUENCE_NUMBER);
        this.startsWithInvalidMessageNumber = startsWithInvalidMessageNumber;
        this.skippsMessageNumbersOnce = skippsMessageNumbersOnce;
        this.skippsMessageNumbersMultiple = skippsMessageNumbersMultiple;
        this.acceptsRandomMessageNumbers = acceptsRandomMessageNumbers;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.STARTS_WITH_INVALID_MESSAGE_SEQUENCE, startsWithInvalidMessageNumber);
        report.putResult(AnalyzedProperty.SKIPPS_MESSAGE_SEQUENCE_ONCE, skippsMessageNumbersOnce);
        report.putResult(AnalyzedProperty.SKIPPS_MESSAGE_SEQUENCE_MULTIPLE, skippsMessageNumbersMultiple);
        report.putResult(AnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_NUMBERS, acceptsRandomMessageNumbers);
        if (skippsMessageNumbersOnce == TestResult.FALSE || skippsMessageNumbersMultiple == TestResult.FALSE
            || acceptsRandomMessageNumbers == TestResult.FALSE) {
            report.putResult(AnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, TestResult.FALSE);
        } else {
            report.putResult(AnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, TestResult.TRUE);
        }
    }

}
