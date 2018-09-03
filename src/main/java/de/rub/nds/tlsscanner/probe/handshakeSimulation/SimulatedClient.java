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
    private boolean receivedServerHello = false;
    private ProtocolVersion highestClientProtocolVersion = null;
    private ProtocolVersion selectedProtocolVersion = null;
    private boolean highestPossibleProtocolVersionSeleceted = false;
    private CipherSuite selectedCiphersuite = null;
    private boolean forwardSecrecy = false;
    private CompressionMethod selectedCompressionMethod = null;
    private EnumSet<ExtensionType> negotiatedExtensionSet = null;
    private boolean receivedCertificate = false;
    private boolean receivedServerKeyExchange = false;
    private String selectedNamedGroup = null;
    private String serverPublicKeyLength = null;
    private boolean receivedCertificateRequest = false;
    private boolean receivedServerHelloDone = false;
    private boolean connectionSecure = true;
    private boolean paddingOracleVulnerable = false;
    private boolean bleichenbacherVulnerable = false;
    private boolean crimeVulnerable = false;
    private boolean invalidCurveVulnerable = false;
    private boolean invalidCurveEphemeralVulnerable = false;
    private boolean sweet32Vulnerable = false;
    
    public SimulatedClient(String type, String version) {
        this.type = type;
        this.version = version;
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

    public boolean isInvalidCurveVulnerable() {
        return invalidCurveVulnerable;
    }

    public void setInvalidCurveVulnerable(boolean invalidCurveVulnerable) {
        this.invalidCurveVulnerable = invalidCurveVulnerable;
    }

    public boolean isInvalidCurveEphemeralVulnerable() {
        return invalidCurveEphemeralVulnerable;
    }

    public void setInvalidCurveEphemeralVulnerable(boolean invalidCurveEphemeralVulnerable) {
        this.invalidCurveEphemeralVulnerable = invalidCurveEphemeralVulnerable;
    }

    public boolean isSweet32Vulnerable() {
        return sweet32Vulnerable;
    }

    public void setSweet32Vulnerable(boolean sweet32Vulnerable) {
        this.sweet32Vulnerable = sweet32Vulnerable;
    }
}
