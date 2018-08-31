/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
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
        int handshakeSuccessfulCounter = 0;
        int handshakeFailedCounter = 0;
        for (SimulatedClient simulatedClient : this.simulatedClientList) {
            if (simulatedClient.isReceivedServerHelloDone() == true) {
                handshakeSuccessfulCounter++;
            } else {
                handshakeFailedCounter++;
            }
            if (simulatedClient.isReceivedServerHello()) {
                if (simulatedClient.getSelectedProtocolVersion().equals(simulatedClient.getHighestClientProtocolVersion())) {
                    simulatedClient.setHighestPossibleProtocolVersionSeleceted(true);
                } else {
                    boolean serverProvidesClientVersion = false;
                    for (ProtocolVersion version : report.getVersions()) {
                        if (version.equals(simulatedClient.getHighestClientProtocolVersion())) {
                            serverProvidesClientVersion = true;
                        }
                    }
                    if (!serverProvidesClientVersion) {
                        simulatedClient.setHighestPossibleProtocolVersionSeleceted(true);
                    }
                }
            }
        }
        report.setHandshakeSuccessfulCounter(handshakeSuccessfulCounter);
        report.setHandshakeFailedCounter(handshakeFailedCounter);
        report.setSimulatedClientList(this.simulatedClientList);
    }
    
}
