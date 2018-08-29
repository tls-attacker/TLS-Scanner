/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.handshakeSimulation;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;

public class SimulatedClient {

    private final String type;
    private final String version;
    private boolean receivedServerHello;
    private CipherSuite selectedCiphersuite;
    
    
    public SimulatedClient(String type, String version) {
        this.type = type;
        this.version = version;
        this.receivedServerHello = false;
        this.selectedCiphersuite = null;
    }

    public String getType() {
        return type;
    }

    public String getVersion() {
        return version;
    }
    
    public void setReceivedServerHello(boolean receivedServerHello) {
        this.receivedServerHello = receivedServerHello;
    }
    
    public boolean isReceivedServerHello() {
        return receivedServerHello;
    }

    public void setSelectedCiphersuite(CipherSuite selectedCiphersuite) {
        this.selectedCiphersuite = selectedCiphersuite;
    }

    public CipherSuite getSelectedCiphersuite() {
        return selectedCiphersuite;
    }
    
}
