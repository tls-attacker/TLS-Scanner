/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.List;

/**
 *
 * @author ic0ns
 */
public class AlpnProbeResult extends ProbeResult {

    private List<String> supportedAlpns;

    public AlpnProbeResult(List<String> supportedAlpns) {
        super(ProbeType.ALPN);
        this.supportedAlpns = supportedAlpns;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.setSupportedAlpns(supportedAlpns);
    }
}
