/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class TlsFallbackScsvResult extends ProbeResult<ServerReport> {

    private final TestResult result;

    public TlsFallbackScsvResult(TestResult result) {
        super(TlsProbeType.TLS_FALLBACK_SCSV);
        this.result = result;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV, result);
    }
}
