/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.EnumSet;

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
    private boolean receivedServerKeyExchange;
    private String selectedNamedGroup;
    private String serverPublicKeyLength;
    private boolean receivedCertificateRequest;
    private boolean receivedServerHelloDone;
    private boolean connectionSecure;
    private boolean paddingOracleVulnerable;
    private boolean bleichenbacherVulnerable;
    private boolean crimeVulnerable;
    private boolean invalidCurveVulnarable;
    private boolean invalidCurveEphemeralVulnarable;
    
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
        this.receivedServerKeyExchange = false;
        this.selectedNamedGroup = null;
        this.serverPublicKeyLength = null;
        this.receivedCertificateRequest = false;
        this.receivedServerHelloDone = false;
        this.connectionSecure = false;
        this.paddingOracleVulnerable = false;
        this.bleichenbacherVulnerable = false;
        this.crimeVulnerable = false;
        this.invalidCurveVulnarable = false;
        this.invalidCurveEphemeralVulnarable = false;
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
    
    public boolean isReceivedServerKeyExchange() {
        return receivedServerKeyExchange;
    }

    public void setReceivedServerKeyExchange(boolean receivedServerKeyExchange) {
        this.receivedServerKeyExchange = receivedServerKeyExchange;
    }
    
    public String getSelectedNamedGroup() {
        return selectedNamedGroup;
    }

    public void setSelectedNamedGroup(String selectedNamedGroup) {
        this.selectedNamedGroup = selectedNamedGroup;
    }
    
    public String getServerPublicKeyLength() {
        return serverPublicKeyLength;
    }

    public void setServerPublicKeyLength(String serverPublicKeyLength) {
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

    public boolean isConnectionSecure() {
        return connectionSecure;
    }

    public void setConnectionSecure(boolean connectionSecure) {
        this.connectionSecure = connectionSecure;
    }
    
    public boolean isPaddingOracleVulnerable() {
        return paddingOracleVulnerable;
    }

    public void setPaddingOracleVulnerable(boolean paddingOracleVulnerable) {
        this.paddingOracleVulnerable = paddingOracleVulnerable;
    }

    public boolean isBleichenbacherVulnerable() {
        return bleichenbacherVulnerable;
    }

    public void setBleichenbacherVulnerable(boolean bleichenbacherVulnerable) {
        this.bleichenbacherVulnerable = bleichenbacherVulnerable;
    }
    
    public boolean isCrimeVulnerable() {
        return crimeVulnerable;
    }

    public void setCrimeVulnerable(boolean crimeVulnerable) {
        this.crimeVulnerable = crimeVulnerable;
    }

    public boolean isInvalidCurveVulnarable() {
        return invalidCurveVulnarable;
    }

    public void setInvalidCurveVulnarable(boolean invalidCurveVulnarable) {
        this.invalidCurveVulnarable = invalidCurveVulnarable;
    }

    public boolean isInvalidCurveEphemeralVulnarable() {
        return invalidCurveEphemeralVulnarable;
    }

    public void setInvalidCurveEphemeralVulnarable(boolean invalidCurveEphemeralVulnarable) {
        this.invalidCurveEphemeralVulnarable = invalidCurveEphemeralVulnarable;
    }
}
