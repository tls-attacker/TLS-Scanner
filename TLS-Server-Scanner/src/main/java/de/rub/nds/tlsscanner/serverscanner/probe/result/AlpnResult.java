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
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.List;

<<<<<<<< HEAD:TLS-Server-Scanner/src/main/java/de/rub/nds/tlsscanner/serverscanner/probe/result/AlpnResult.java
public class AlpnResult extends ProbeResult {
========
/**
 *
 * @author ic0ns
 */
public class AlpnProbeResult extends ProbeResult<SiteReport> {
>>>>>>>> dae7150d1 (reworked client scanner):TLS-Server-Scanner/src/main/java/de/rub/nds/tlsscanner/serverscanner/probe/result/AlpnProbeResult.java

    private final List<String> supportedAlpns;

<<<<<<<< HEAD:TLS-Server-Scanner/src/main/java/de/rub/nds/tlsscanner/serverscanner/probe/result/AlpnResult.java
    public AlpnResult(List<String> supportedAlpns) {
        super(ProbeType.ALPN);
========
    public AlpnProbeResult(List<String> supportedAlpns) {
        super(TlsProbeType.ALPN);
>>>>>>>> dae7150d1 (reworked client scanner):TLS-Server-Scanner/src/main/java/de/rub/nds/tlsscanner/serverscanner/probe/result/AlpnProbeResult.java
        this.supportedAlpns = supportedAlpns;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.setSupportedAlpns(supportedAlpns);
    }
}
