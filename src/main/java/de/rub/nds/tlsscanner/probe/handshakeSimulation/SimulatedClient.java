/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.EnumSet;
import org.bouncycastle.crypto.tls.Certificate;

public class SimulatedClient {

    private final String type;
    private final String version;
    private boolean receivedServerHello;
    private ProtocolVersion highestClientProtocolVersion;
    private ProtocolVersion selectedProtocolVersion;
    private boolean highestPossibleProtocolVersionSeleceted;
    private CipherSuite selectedCiphersuite;
    private boolean forwardSecrecy;
    private CompressionMethod selectedCompressionMethod;
    private EnumSet<ExtensionType> negotiatedExtensionSet;
    private boolean receivedCertificate;
    private Certificate serverCertificate;
    private boolean receivedServerKeyExchange;
    private NamedGroup selectedNamedGroup;
    private int serverPublicKeyLength;
    private boolean receivedCertificateRequest;
    private boolean receivedServerHelloDone;
    
    public SimulatedClient(String type, String version) {
        this.type = type;
        this.version = version;
        this.receivedServerHello = false;
        this.highestClientProtocolVersion = null;
        this.selectedProtocolVersion = null;
        this.highestPossibleProtocolVersionSeleceted = false;
        this.selectedCiphersuite = null;
        this.forwardSecrecy = false;
        this.selectedCompressionMethod = null;
        this.negotiatedExtensionSet = null;
        this.receivedCertificate = false;
        this.serverCertificate = null;
        this.receivedServerKeyExchange = false;
        this.selectedNamedGroup = null;
        this.serverPublicKeyLength = 0;
        this.receivedCertificateRequest = false;
        this.receivedServerHelloDone = false;
    }

    public String getType() {
        return type;
    }

    public String getVersion() {
        return version;
    }
    
    public boolean isReceivedServerHello() {
        return receivedServerHello;
    }
    
    public void setReceivedServerHello(boolean receivedServerHello) {
        this.receivedServerHello = receivedServerHello;
    }
    
    public ProtocolVersion getHighestClientProtocolVersion() {
        return highestClientProtocolVersion;
    }

    public void setHighestClientProtocolVersion(ProtocolVersion highestClientProtocolVersion) {
        this.highestClientProtocolVersion = highestClientProtocolVersion;
    }
    
    public ProtocolVersion getSelectedProtocolVersion() {
        return selectedProtocolVersion;
    }
    
    public void setSelectedProtocolVersion(ProtocolVersion selectedProtocolVersion) {
        this.selectedProtocolVersion = selectedProtocolVersion;
    }
    
    public boolean isHighestPossibleProtocolVersionSeleceted() {
        return highestPossibleProtocolVersionSeleceted;
    }

    public void setHighestPossibleProtocolVersionSeleceted(boolean highestPossibleProtocolVersionSeleceted) {
        this.highestPossibleProtocolVersionSeleceted = highestPossibleProtocolVersionSeleceted;
    }
    
    public CipherSuite getSelectedCiphersuite() {
        return selectedCiphersuite;
    }

    public void setSelectedCiphersuite(CipherSuite selectedCiphersuite) {
        this.selectedCiphersuite = selectedCiphersuite;
    }
    
    public boolean isForwardSecrecy() {
        return forwardSecrecy;
    }
    
    public void setForwardSecrecy(boolean forwardSecrecy) {
        this.forwardSecrecy = forwardSecrecy;
    }
    
    public CompressionMethod getSelectedCompressionMethod() {
        return selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(CompressionMethod selectedCompressionMethod) {
        this.selectedCompressionMethod = selectedCompressionMethod;
    }
    
    public EnumSet<ExtensionType> getNegotiatedExtensionSet() {
        return negotiatedExtensionSet;
    }

    public void setNegotiatedExtensionSet(EnumSet<ExtensionType> negotiatedExtensionSet) {
        this.negotiatedExtensionSet = negotiatedExtensionSet;
    }
    
    public boolean isReceivedCertificate() {
        return receivedCertificate;
    }

    public void setReceivedCertificate(boolean receivedCertificate) {
        this.receivedCertificate = receivedCertificate;
    }
    
    public Certificate getServerCertificate() {
        return serverCertificate;
    }

    public void setServerCertificate(Certificate serverCertificate) {
        this.serverCertificate = serverCertificate;
    }
    
    public boolean isReceivedServerKeyExchange() {
        return receivedServerKeyExchange;
    }

    public void setReceivedServerKeyExchange(boolean receivedServerKeyExchange) {
        this.receivedServerKeyExchange = receivedServerKeyExchange;
    }
    
    public NamedGroup getSelectedNamedGroup() {
        return selectedNamedGroup;
    }

    public void setSelectedNamedGroup(NamedGroup selectedNamedGroup) {
        this.selectedNamedGroup = selectedNamedGroup;
    }
    
    public int getServerPublicKeyLength() {
        return serverPublicKeyLength;
    }

    public void setServerPublicKeyLength(int serverPublicKeyLength) {
        this.serverPublicKeyLength = serverPublicKeyLength;
    }
    
    public boolean isReceivedCertificateRequest() {
        return receivedCertificateRequest;
    }

    public void setReceivedCertificateRequest(boolean receivedCertificateRequest) {
        this.receivedCertificateRequest = receivedCertificateRequest;
    }
    
    public boolean isReceivedServerHelloDone() {
        return receivedServerHelloDone;
    }
    
    public void setReceivedServerHelloDone(boolean receivedServerHelloDone) {
        this.receivedServerHelloDone = receivedServerHelloDone;
    }
}
