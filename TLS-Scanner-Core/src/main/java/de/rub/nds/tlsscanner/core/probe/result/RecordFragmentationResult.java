/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

public class RecordFragmentationResult<Report extends TlsScanReport> extends ProbeResult<Report> {

    private TestResult supportsRecordFragmentation = null;

    public RecordFragmentationResult(TestResult supported) {
        super(TlsProbeType.RECORD_FRAGMENTATION);
        this.supportsRecordFragmentation = supported;
    }

    @Override
    protected void mergeData(Report report) {
        report.putResult(
                TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION, supportsRecordFragmentation);
    }
}
