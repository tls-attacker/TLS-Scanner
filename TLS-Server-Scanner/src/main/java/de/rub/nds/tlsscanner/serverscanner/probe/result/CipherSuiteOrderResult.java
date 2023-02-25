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

public class CipherSuiteOrderResult extends ProbeResult<ServerReport> {

    private TestResult enforced;

    public CipherSuiteOrderResult(TestResult enforced) {
        super(TlsProbeType.CIPHER_SUITE_ORDER);
        this.enforced = enforced;
    }

    @Override
    public void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.ENFORCES_CS_ORDERING, enforced);
    }
}
