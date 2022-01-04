/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class DtlsFeaturesResult extends ProbeResult {

    private TestResult supportsFragmentation;
    private TestResult supportsReordering;

    public DtlsFeaturesResult(TestResult supportsFragmentation, TestResult supportsReordering) {
        super(ProbeType.DTLS_FEATURES);
        this.supportsFragmentation = supportsFragmentation;
        this.supportsReordering = supportsReordering;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, supportsFragmentation);
        report.putResult(AnalyzedProperty.SUPPORTS_REORDERING, supportsReordering);
    }

}