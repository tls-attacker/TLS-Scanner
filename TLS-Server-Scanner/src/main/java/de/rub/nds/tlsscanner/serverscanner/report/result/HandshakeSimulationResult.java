/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakeSimulation.SimulatedClientResult;
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
