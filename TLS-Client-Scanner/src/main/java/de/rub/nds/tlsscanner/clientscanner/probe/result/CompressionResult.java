/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.List;

public class CompressionResult extends ProbeResult<ClientReport> {

    private final List<CompressionMethod> supportedCompressions;
    private final TestResult forcedCompression;

    public CompressionResult(
            List<CompressionMethod> supportedCompressions, TestResult forcedCompression) {
        super(TlsProbeType.COMPRESSIONS);
        this.supportedCompressions = supportedCompressions;
        this.forcedCompression = forcedCompression;
    }

    @Override
    protected void mergeData(ClientReport report) {
        if (supportedCompressions != null) {
            report.setSupportedCompressionMethods(supportedCompressions);
            if (supportedCompressions.contains(CompressionMethod.LZS)
                    || supportedCompressions.contains(CompressionMethod.DEFLATE)) {
                report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, TestResults.TRUE);
                report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResults.TRUE);
            } else {
                report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, TestResults.FALSE);
                report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResults.FALSE);
            }
        } else {
            report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, TestResults.COULD_NOT_TEST);
            report.putResult(
                    TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResults.COULD_NOT_TEST);
        }
        report.putResult(TlsAnalyzedProperty.FORCED_COMPRESSION, forcedCompression);
    }
}
