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
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

public class ForcedCompressionResult extends ProbeResult<ClientReport> {

    private final TestResult canForceCompression;

    public ForcedCompressionResult(TestResult canForceCompression) {
        super(TlsProbeType.FORCED_COMPRESSION);
        this.canForceCompression = canForceCompression;
    }

    @Override
    protected void mergeData(ClientReport report) {

    }

}
