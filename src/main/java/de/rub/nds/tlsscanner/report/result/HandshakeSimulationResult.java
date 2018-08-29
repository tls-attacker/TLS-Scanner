/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.handshakeSimulation.SimulatedClient;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

public class HandshakeSimulationResult extends ProbeResult {

    private final List<SimulatedClient> simulatedClientList;
    
    public HandshakeSimulationResult(List<SimulatedClient> simulatedClientList) {
        super(ProbeType.HANDSHAKE_SIMULATION);
        this.simulatedClientList = simulatedClientList;
    }

    @Override
    public void merge(SiteReport report) {
        report.setSimulatedClientList(this.simulatedClientList);
    }
    
}
