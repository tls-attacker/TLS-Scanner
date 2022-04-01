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
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class DtlsFeaturesResult extends ProbeResult<ServerReport> {

    private TestResult supportsFragmentation;
    private TestResult supportsReordering;

    public DtlsFeaturesResult(TestResult supportsFragmentation, TestResult supportsReordering) {
        super(TlsProbeType.DTLS_FEATURES);
        this.supportsFragmentation = supportsFragmentation;
        this.supportsReordering = supportsReordering;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, supportsFragmentation);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_REORDERING, supportsReordering);
    }

}