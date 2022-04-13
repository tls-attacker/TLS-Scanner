/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class DtlsMessageSequenceResult extends ProbeResult<ServerReport> {

    private TestResult acceptsStartedWithInvalidMessageNumber;
    private TestResult acceptsSkippedMessageNumbersOnce;
    private TestResult acceptsSkippedMessageNumbersMultiple;
    private TestResult acceptsRandomMessageNumbers;

    public DtlsMessageSequenceResult(TestResult acceptsStartedWithInvalidMessageNumber,
        TestResult acceptsSkippedMessageNumbersOnce, TestResult acceptsSkippedMessageNumbersMultiple,
        TestResult acceptsRandomMessageNumbers) {
        super(TlsProbeType.DTLS_MESSAGE_SEQUENCE_NUMBER);
        this.acceptsStartedWithInvalidMessageNumber = acceptsStartedWithInvalidMessageNumber;
        this.acceptsSkippedMessageNumbersOnce = acceptsSkippedMessageNumbersOnce;
        this.acceptsSkippedMessageNumbersMultiple = acceptsSkippedMessageNumbersMultiple;
        this.acceptsRandomMessageNumbers = acceptsRandomMessageNumbers;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE,
            acceptsStartedWithInvalidMessageNumber);
        report.putResult(TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE, acceptsSkippedMessageNumbersOnce);
        report.putResult(TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE,
            acceptsSkippedMessageNumbersMultiple);
        report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, acceptsRandomMessageNumbers);
        if (acceptsSkippedMessageNumbersOnce == TestResults.FALSE
            && acceptsSkippedMessageNumbersMultiple == TestResults.FALSE
            && acceptsRandomMessageNumbers == TestResults.FALSE) {
            report.putResult(TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, TestResults.FALSE);
        } else {
            report.putResult(TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, TestResults.TRUE);
        }
    }

}
