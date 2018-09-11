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
    private Boolean receivedServerHello = null;
    private ProtocolVersion highestClientProtocolVersion = null;
    private ProtocolVersion selectedProtocolVersion = null;
    private Boolean highestPossibleProtocolVersionSeleceted = null;
    private CipherSuite selectedCiphersuite = null;
    private Boolean forwardSecrecy = null;
    private CompressionMethod selectedCompressionMethod = null;
    private EnumSet<ExtensionType> negotiatedExtensionSet = null;
    private Boolean receivedCertificate = null;
    private Boolean receivedServerKeyExchange = null;
    private String selectedNamedGroup = null;
    private String serverPublicKeyLength = null;
    private Boolean receivedCertificateRequest = null;
    private Boolean receivedServerHelloDone = null;
    private Boolean connectionSecure = null;
    private Boolean paddingOracleVulnerable = null;
    private Boolean bleichenbacherVulnerable = null;
    private Boolean crimeVulnerable = null;
    private Boolean sweet32Vulnerable = null;
    private Boolean drownVulnerable = null;
    
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
    
    public Boolean getReceivedServerHello() {
        return receivedServerHello;
    }
    
    public void setReceivedServerHello(Boolean receivedServerHello) {
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
    
    public Boolean getHighestPossibleProtocolVersionSeleceted() {
        return highestPossibleProtocolVersionSeleceted;
    }

    public void setHighestPossibleProtocolVersionSeleceted(Boolean highestPossibleProtocolVersionSeleceted) {
        this.highestPossibleProtocolVersionSeleceted = highestPossibleProtocolVersionSeleceted;
    }
    
    public CipherSuite getSelectedCiphersuite() {
        return selectedCiphersuite;
    }

    public void setSelectedCiphersuite(CipherSuite selectedCiphersuite) {
        this.selectedCiphersuite = selectedCiphersuite;
    }
    
    public Boolean getForwardSecrecy() {
        return forwardSecrecy;
    }
    
    public void setForwardSecrecy(Boolean forwardSecrecy) {
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
    
    public Boolean getReceivedCertificate() {
        return receivedCertificate;
    }

    public void setReceivedCertificate(Boolean receivedCertificate) {
        this.receivedCertificate = receivedCertificate;
    }
    
    public Boolean getReceivedServerKeyExchange() {
        return receivedServerKeyExchange;
    }

    public void setReceivedServerKeyExchange(Boolean receivedServerKeyExchange) {
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
    
    public Boolean getReceivedCertificateRequest() {
        return receivedCertificateRequest;
    }

    public void setReceivedCertificateRequest(Boolean receivedCertificateRequest) {
        this.receivedCertificateRequest = receivedCertificateRequest;
    }
    
    public Boolean getReceivedServerHelloDone() {
        return receivedServerHelloDone;
    }
    
    public void setReceivedServerHelloDone(Boolean receivedServerHelloDone) {
        this.receivedServerHelloDone = receivedServerHelloDone;
    }

    public Boolean getConnectionSecure() {
        return connectionSecure;
    }

    public void setConnectionSecure(Boolean connectionSecure) {
        this.connectionSecure = connectionSecure;
    }
    
    public Boolean getPaddingOracleVulnerable() {
        return paddingOracleVulnerable;
    }

    public void setPaddingOracleVulnerable(Boolean paddingOracleVulnerable) {
        this.paddingOracleVulnerable = paddingOracleVulnerable;
    }

    public Boolean getBleichenbacherVulnerable() {
        return bleichenbacherVulnerable;
    }

    public void setBleichenbacherVulnerable(Boolean bleichenbacherVulnerable) {
        this.bleichenbacherVulnerable = bleichenbacherVulnerable;
    }
    
    public Boolean getCrimeVulnerable() {
        return crimeVulnerable;
    }

    public void setCrimeVulnerable(Boolean crimeVulnerable) {
        this.crimeVulnerable = crimeVulnerable;
    }

    public Boolean getSweet32Vulnerable() {
        return sweet32Vulnerable;
    }

    public void setSweet32Vulnerable(Boolean sweet32Vulnerable) {
        this.sweet32Vulnerable = sweet32Vulnerable;
    }

    public Boolean getDrownVulnerable() {
        return drownVulnerable;
    }

    public void setDrownVulnerable(Boolean drownVulnerable) {
        this.drownVulnerable = drownVulnerable;
    }
}
