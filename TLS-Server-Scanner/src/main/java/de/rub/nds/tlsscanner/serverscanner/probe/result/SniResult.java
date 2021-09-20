/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class SniResult extends ProbeResult<SiteReport> {

    private TestResult requiresSni;

    public SniResult(TestResult requiresSni) {
        super(TlsProbeType.SNI);
        this.requiresSni = requiresSni;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(TlsAnalyzedProperty.REQUIRES_SNI, requiresSni);
    }

}
