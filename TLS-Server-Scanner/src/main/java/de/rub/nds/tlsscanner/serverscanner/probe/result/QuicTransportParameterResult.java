/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class QuicTransportParameterResult extends ProbeResult<ServerReport> {

    private final QuicTransportParameters transportParameters;

    public QuicTransportParameterResult(ProbeType type, QuicTransportParameters transportParameters) {
        super(type);
        this.transportParameters = transportParameters;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setQuicTransportParameters(transportParameters);
    }

    public QuicTransportParameters getTransportParameters() {
        return transportParameters;
    }



}
