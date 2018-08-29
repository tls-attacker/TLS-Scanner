/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.handshakeSimulation.TlsClientConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.LinkedList;
import java.util.List;

public class HandshakeSimulationResult extends ProbeResult {

    private final List<TlsClientConfig> clientConfigList;
    private final List<CipherSuite> selectedCiphersuiteList;
    
    public HandshakeSimulationResult(List<TlsClientConfig> clientConfigList, List<CipherSuite> selectedCiphersuiteList) {
        super(ProbeType.HANDSHAKE_SIMULATION);
        this.clientConfigList = clientConfigList;
        this.selectedCiphersuiteList = selectedCiphersuiteList;
    }

    @Override
    public void merge(SiteReport report) {
        List<String> testedClients = new LinkedList<>();
        for (TlsClientConfig clientConfig : this.clientConfigList)  {
            testedClients.add(clientConfig.getType() + ":" + clientConfig.getVersion());
        }
        report.setTestedClientList(testedClients);
        report.setSelectedCiphersuiteList(this.selectedCiphersuiteList);
    }
    
}
