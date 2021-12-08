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

public class DtlsMessageSequenceResult extends ProbeResult {

    private TestResult acceptsStartedWithInvalidMessageNumber;
    private TestResult acceptsSkippedMessageNumbersOnce;
    private TestResult acceptsSkippedMessageNumbersMultiple;
    private TestResult acceptsRandomMessageNumbers;

    public DtlsMessageSequenceResult(TestResult acceptsStartedWithInvalidMessageNumber,
        TestResult acceptsSkippedMessageNumbersOnce, TestResult acceptsSkippedMessageNumbersMultiple,
        TestResult acceptsRandomMessageNumbers) {
        super(ProbeType.DTLS_MESSAGE_SEQUENCE_NUMBER);
        this.acceptsStartedWithInvalidMessageNumber = acceptsStartedWithInvalidMessageNumber;
        this.acceptsSkippedMessageNumbersOnce = acceptsSkippedMessageNumbersOnce;
        this.acceptsSkippedMessageNumbersMultiple = acceptsSkippedMessageNumbersMultiple;
        this.acceptsRandomMessageNumbers = acceptsRandomMessageNumbers;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE,
            acceptsStartedWithInvalidMessageNumber);
        report.putResult(AnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE, acceptsSkippedMessageNumbersOnce);
        report.putResult(AnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE,
            acceptsSkippedMessageNumbersMultiple);
        report.putResult(AnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, acceptsRandomMessageNumbers);
        if (acceptsSkippedMessageNumbersOnce == TestResult.FALSE
            || acceptsSkippedMessageNumbersMultiple == TestResult.FALSE
            || acceptsRandomMessageNumbers == TestResult.FALSE) {
            report.putResult(AnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, TestResult.FALSE);
        } else {
            report.putResult(AnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, TestResult.TRUE);
        }
    }

}
