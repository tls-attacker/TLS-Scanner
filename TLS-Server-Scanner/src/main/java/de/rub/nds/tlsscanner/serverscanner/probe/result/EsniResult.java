/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.scanner.core.probe.result.ProbeResult;

public class EsniResult extends ProbeResult<SiteReport> {
    private TestResult receivedCorrectNonce;

    public EsniResult(TestResult receivedCorrectNonce) {
        super(TlsProbeType.ESNI);
        this.receivedCorrectNonce = receivedCorrectNonce;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ESNI, receivedCorrectNonce);
    }
}
