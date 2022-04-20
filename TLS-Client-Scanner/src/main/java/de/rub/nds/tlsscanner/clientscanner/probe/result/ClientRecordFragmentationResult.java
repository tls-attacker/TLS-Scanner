/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;

public class ClientRecordFragmentationResult extends ProbeResult<ClientReport> {
    private final TestResult supportsRecordFragmentation;

    public ClientRecordFragmentationResult(TestResult supportsRecordFragmentation) {
        super(TlsProbeType.RECORD_FRAGMENTATION);

        this.supportsRecordFragmentation = supportsRecordFragmentation;
    }

    @Override
    protected void mergeData(ClientReport report) {
        report.putResult(TlsAnalyzedProperty.RECORD_FRAGMENTATION, supportsRecordFragmentation);
    }

}
