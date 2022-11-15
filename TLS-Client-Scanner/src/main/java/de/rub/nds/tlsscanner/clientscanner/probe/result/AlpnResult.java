/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.List;

public class AlpnResult extends ProbeResult<ClientReport> {

    private final List<String> clientAdvertisedAlpnList;
    private final TestResult strictAlpn;

    public AlpnResult(List<String> clientAdvertisedAlpnList, TestResult strictAlpn) {
        super(TlsProbeType.ALPN);
        this.clientAdvertisedAlpnList = clientAdvertisedAlpnList;
        this.strictAlpn = strictAlpn;
    }

    @Override
    protected void mergeData(ClientReport report) {
        report.setClientAdvertisedAlpns(clientAdvertisedAlpnList);
        report.putResult(TlsAnalyzedProperty.STRICT_ALPN, strictAlpn);
    }
}
