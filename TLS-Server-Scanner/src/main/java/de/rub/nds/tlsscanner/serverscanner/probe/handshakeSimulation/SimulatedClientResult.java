/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe.handshakeSimulation;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.LinkedList;
import java.util.List;

public class SimulatedClientResult {

    // To set in HandshakeSimulationProbe
    private Boolean receivedServerHello = null;
    private Boolean receivedCertificate = null;
    private Boolean receivedServerKeyExchange = null;
    private Boolean receivedCertificateRequest = null;
    private Boolean receivedServerHelloDone = null;
    private Boolean receivedAlert = null;
    private Boolean receivedUnknown = null;
    private Boolean receivedAllMandatoryMessages = null;
    private ProtocolVersion highestClientProtocolVersion = null;
    private ProtocolVersion selectedProtocolVersion = null;
    private List<ProtocolVersion> commonProtocolVersions = null;
    private List<CipherSuite> clientSupportedCiphersuites = null;
    private CipherSuite selectedCiphersuite = null;
    private KeyExchangeAlgorithm keyExchangeAlgorithm = null;
    private Boolean forwardSecrecy = null;
    private CompressionMethod selectedCompressionMethod = null;
    private String negotiatedExtensions = null;
    private List<String> alpnAnnouncedProtocols = null;
    private String selectedNamedGroup = null;
    private Integer serverPublicKeyParameter = null;
    private List<ProtocolVersion> supportedVersionList = null;
    private List<ProtocolVersion> versionAcceptForbiddenCiphersuiteList = null;
    private List<Integer> supportedRsaKeySizeList = null;
    private List<Integer> supportedDheKeySizeList = null;

    // private final State state;

    // private final TlsClientConfig tlsClientConfig;

    // To set in HandshakeSimulationAfterProbe
    private Boolean highestPossibleProtocolVersionSeleceted = null;
    private Boolean handshakeSuccessful = null;
    private Boolean connectionInsecure = null;
    private Boolean connectionRfc7918Secure = null;
    private List<HandshakeFailureReasons> failureReasons = null;
    private List<String> insecureReasons = null;

    private SimulatedClientResult() {
        // tlsClientConfig = null;
    }

    public SimulatedClientResult(TlsClientConfig tlsClientConfig) {
        // this.tlsClientConfig = tlsClientConfig;
        this.failureReasons = new LinkedList<>();
        this.insecureReasons = new LinkedList<>();
    }

    public TlsClientConfig getTlsClientConfig() {
        return null;
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

    public Boolean getReceivedAlert() {
        return receivedAlert;
    }

    public void setReceivedAlert(Boolean receivedAlert) {
        this.receivedAlert = receivedAlert;
    }

    public Boolean getReceivedUnknown() {
        return receivedUnknown;
    }

    public void setReceivedUnknown(Boolean receivedUnknown) {
        this.receivedUnknown = receivedUnknown;
    }

    public Boolean getReceivedAllMandatoryMessages() {
        return receivedAllMandatoryMessages;
    }

    public void setReceivedAllMandatoryMessages(Boolean receivedAllMandatoryMessages) {
        this.receivedAllMandatoryMessages = receivedAllMandatoryMessages;
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

    public List<ProtocolVersion> getCommonProtocolVersions() {
        return commonProtocolVersions;
    }

    public void setCommonProtocolVersions(List<ProtocolVersion> commonProtocolVersions) {
        this.commonProtocolVersions = commonProtocolVersions;
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

    public KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
        return keyExchangeAlgorithm;
    }

    public void setKeyExchangeAlgorithm(KeyExchangeAlgorithm keyExchangeAlgorithm) {
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
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

    public List<String> getAlpnAnnouncedProtocols() {
        return alpnAnnouncedProtocols;
    }

    public void setAlpnAnnouncedProtocols(List<String> alpnAnnouncedProtocols) {
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

    public List<HandshakeFailureReasons> getFailReasons() {
        return failureReasons;
    }

    public void addToFailReasons(HandshakeFailureReasons handshakeFailureReason) {
        failureReasons.add(handshakeFailureReason);
    }

    public List<String> getInsecureReasons() {
        return insecureReasons;
    }

    public void addToInsecureReasons(String handshakeIssue) {
        insecureReasons.add(handshakeIssue);
    }
}
