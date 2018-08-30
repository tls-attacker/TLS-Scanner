/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.handshakeSimulation;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

public class SimulatedClient {

    private final String type;
    private final String version;
    private boolean receivedServerHello;
    private ProtocolVersion selectedProtocolVersion;
    private CipherSuite selectedCiphersuite;
    private CompressionMethod selectedCompressionMethod;
    private NamedGroup selectedNamedGroup;
    
    public SimulatedClient(String type, String version) {
        this.type = type;
        this.version = version;
        this.receivedServerHello = false;
        this.selectedCiphersuite = null;
        this.selectedCompressionMethod = null;
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
    
    public void setSelectedProtocolVersion(ProtocolVersion selectedProtocolVersion) {
        this.selectedProtocolVersion = selectedProtocolVersion;
    }

    public ProtocolVersion getSelectedProtocolVersion() {
        return selectedProtocolVersion;
    }

    public void setSelectedCiphersuite(CipherSuite selectedCiphersuite) {
        this.selectedCiphersuite = selectedCiphersuite;
    }

    public CipherSuite getSelectedCiphersuite() {
        return selectedCiphersuite;
    }

    public void setSelectedCompressionMethod(CompressionMethod selectedCompressionMethod) {
        this.selectedCompressionMethod = selectedCompressionMethod;
    }

    public CompressionMethod getSelectedCompressionMethod() {
        return selectedCompressionMethod;
    }

    public void setSelectedNamedGroup(NamedGroup selectedNamedGroup) {
        this.selectedNamedGroup = selectedNamedGroup;
    }

    public NamedGroup getSelectedNamedGroup() {
        return selectedNamedGroup;
    }
    
}
