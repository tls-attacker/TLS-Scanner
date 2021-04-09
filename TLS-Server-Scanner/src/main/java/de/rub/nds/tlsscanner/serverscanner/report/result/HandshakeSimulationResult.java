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
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.List;

public class HandshakeSimulationResult extends ProbeResult {

    private final List<SimulatedClientResult> simulatedClientList;

    public HandshakeSimulationResult(List<SimulatedClientResult> simulatedClientList) {
        super(ProbeType.HANDSHAKE_SIMULATION);
        this.simulatedClientList = simulatedClientList;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setSimulatedClientList(simulatedClientList);
    }
}
