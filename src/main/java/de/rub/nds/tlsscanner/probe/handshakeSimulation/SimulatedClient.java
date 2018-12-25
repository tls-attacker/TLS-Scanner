/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;

public class SimulatedClient {

    private final String type;
    private final String version;
    private final boolean defaultVersion;
    //To set in HandshakeSimulationProbe
    private Boolean receivedServerHello = null;
    private Boolean receivedCertificate = null;
    private Boolean receivedServerKeyExchange = null;
    private Boolean receivedCertificateRequest = null;
    private Boolean receivedServerHelloDone = null;
    private Boolean receivedUnknown = null;
    private ProtocolVersion highestClientProtocolVersion = null;
    private ProtocolVersion selectedProtocolVersion = null;
    private List<CipherSuite> clientSupportedCiphersuites = null;
    private CipherSuite selectedCiphersuite = null;
    private Boolean forwardSecrecy = null;
    private CompressionMethod selectedCompressionMethod = null;
    private String negotiatedExtensions = null;
    private String alpnAnnouncedProtocols = null;
    private String selectedNamedGroup = null;
    private Integer serverPublicKeyParameter = null;
    private List<ProtocolVersion> supportedVersionList = null;
    private List<ProtocolVersion> versionAcceptForbiddenCiphersuiteList = null;
    private List<Integer> supportedRsaKeySizeList = null;
    private List<Integer> supportedDheKeySizeList = null;
    //To set in HandshakeSimulationAfterProbe
    private Boolean highestPossibleProtocolVersionSeleceted = null;
    private Boolean handshakeSuccessful = null;
    private Boolean connectionInsecure = null;
    private Boolean connectionRfc7918Secure = null;
    private List<String> failReasons = null;
    private List<String> insecureReasons = null;

    public SimulatedClient(String type, String version, boolean defaultVersion) {
        this.type = type;
        this.version = version;
        this.defaultVersion = defaultVersion;
        this.failReasons = new LinkedList<>();
        this.insecureReasons = new LinkedList<>();
    }

    public String getType() {
        return type;
    }

    public String getVersion() {
        return version;
    }

    public boolean isDefaultVersion() {
        return defaultVersion;
    }

    public Boolean getReceivedServerHello() {
        return receivedServerHello;
    }

    public void setReceivedServerHello(Boolean receivedServerHello) {
        this.receivedServerHello = receivedServerHello;
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

    public Boolean getReceivedUnknown() {
        return receivedUnknown;
    }

    public void setReceivedUnknown(Boolean receivedUnknown) {
        this.receivedUnknown = receivedUnknown;
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

    public List<CipherSuite> getClientSupportedCiphersuites() {
        return clientSupportedCiphersuites;
    }

    public void setClientSupportedCiphersuites(List<CipherSuite> clientSupportedCiphersuites) {
        this.clientSupportedCiphersuites = clientSupportedCiphersuites;
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

    public String getNegotiatedExtensions() {
        return negotiatedExtensions;
    }

    public void setNegotiatedExtensions(String negotiatedExtensions) {
        this.negotiatedExtensions = negotiatedExtensions;
    }

    public String getAlpnAnnouncedProtocols() {
        return alpnAnnouncedProtocols;
    }

    public void setAlpnAnnouncedProtocols(String alpnAnnouncedProtocols) {
        this.alpnAnnouncedProtocols = alpnAnnouncedProtocols;
    }

    public String getSelectedNamedGroup() {
        return selectedNamedGroup;
    }

    public void setSelectedNamedGroup(String selectedNamedGroup) {
        this.selectedNamedGroup = selectedNamedGroup;
    }

    public Integer getServerPublicKeyParameter() {
        return serverPublicKeyParameter;
    }

    public void setServerPublicKeyParameter(Integer serverPublicKeyParameter) {
        this.serverPublicKeyParameter = serverPublicKeyParameter;
    }

    public List<ProtocolVersion> getSupportedVersionList() {
        return supportedVersionList;
    }

    public void setSupportedVersionList(List<ProtocolVersion> supportedVersionList) {
        this.supportedVersionList = supportedVersionList;
    }

    public List<ProtocolVersion> getVersionAcceptForbiddenCiphersuiteList() {
        return versionAcceptForbiddenCiphersuiteList;
    }

    public void setVersionAcceptForbiddenCiphersuiteList(List<ProtocolVersion> versionAcceptForbiddenCiphersuiteList) {
        this.versionAcceptForbiddenCiphersuiteList = versionAcceptForbiddenCiphersuiteList;
    }

    public List<Integer> getSupportedRsaKeySizeList() {
        return supportedRsaKeySizeList;
    }

    public void setSupportedRsaKeySizeList(List<Integer> supportedRsaKeySizeList) {
        this.supportedRsaKeySizeList = supportedRsaKeySizeList;
    }

    public List<Integer> getSupportedDheKeySizeList() {
        return supportedDheKeySizeList;
    }

    public void setSupportedDheKeySizeList(List<Integer> supportedDheKeySizeList) {
        this.supportedDheKeySizeList = supportedDheKeySizeList;
    }

    public Boolean getHandshakeSuccessful() {
        return handshakeSuccessful;
    }

    public void setHandshakeSuccessful(Boolean handshakeSuccessful) {
        this.handshakeSuccessful = handshakeSuccessful;
    }

    public Boolean getConnectionInsecure() {
        return connectionInsecure;
    }

    public void setConnectionInsecure(Boolean connectionInsecure) {
        this.connectionInsecure = connectionInsecure;
    }

    public Boolean getConnectionRfc7918Secure() {
        return connectionRfc7918Secure;
    }

    public void setConnectionRfc7918Secure(Boolean connectionRfc7918Secure) {
        this.connectionRfc7918Secure = connectionRfc7918Secure;
    }

    public List<String> getFailReasons() {
        return failReasons;
    }

    public void addToFailReasons(String handshakeIssue) {
        failReasons.add(handshakeIssue);
    }

    public List<String> getInsecureReasons() {
        return insecureReasons;
    }

    public void addToInsecureReasons(String handshakeIssue) {
        insecureReasons.add(handshakeIssue);
    }
}
