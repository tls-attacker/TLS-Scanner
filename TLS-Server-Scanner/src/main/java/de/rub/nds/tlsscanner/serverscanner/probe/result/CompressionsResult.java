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
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.List;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class CompressionsResult extends ProbeResult<ServerReport> {

    private List<CompressionMethod> compressions;

    public CompressionsResult(List<CompressionMethod> compressions) {
        super(TlsProbeType.COMPRESSIONS);
        this.compressions = compressions;
    }

    @Override
    public void mergeData(ServerReport report) {
        if (compressions != null) {
            report.setSupportedCompressionMethods(compressions);
            if (compressions.contains(CompressionMethod.LZS) || compressions.contains(CompressionMethod.DEFLATE)) {
                report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, TestResult.TRUE);
                report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResult.TRUE);
            } else {
                report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, TestResult.FALSE);
                report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResult.FALSE);
            }
        } else {
            report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, TestResult.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResult.COULD_NOT_TEST);
        }
    }

}
