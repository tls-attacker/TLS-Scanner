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

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class HeartbleedResult extends ProbeResult<ServerReport> {

    private TestResult vulnerable;

    public HeartbleedResult(TestResult vulnerable) {
        super(TlsProbeType.HEARTBLEED);
        this.vulnerable = vulnerable;
    }

    @Override
    public void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED, vulnerable);
    }
}
