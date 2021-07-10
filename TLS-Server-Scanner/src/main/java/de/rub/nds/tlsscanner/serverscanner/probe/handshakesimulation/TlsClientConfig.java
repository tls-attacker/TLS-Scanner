/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation;

import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;

import java.io.InputStream;
import java.io.Serializable;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class TlsClientConfig implements Serializable {

    private String type;
    private String version;
    private Boolean defaultVersion;
    private Config config;
    private WorkflowTrace trace;
    private List<ProtocolVersion> supportedVersionList;
    private List<ProtocolVersion> versionAcceptForbiddenCipherSuiteList;
    private List<Integer> supportedRsaKeySizeList;
    private List<Integer> supportedDheKeySizeList;
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] initialBytes;
    private Boolean isSSL2CompatibleClientHello = false;

    public static TlsClientConfig createTlsClientConfig(String resourcePath) {
        InputStream stream = ConfigFileList.class.getResourceAsStream(resourcePath);
        return TlsClientConfigIO.read(stream);
    }

    public void createTlsClientConfig(String type, String version) {
        this.type = type;
        this.version = version;
        this.defaultVersion = null;
        this.config = null;
        this.trace = null;
        this.supportedVersionList = null;
        this.versionAcceptForbiddenCipherSuiteList = null;
        this.supportedVersionList = null;
        this.supportedRsaKeySizeList = null;
        this.supportedDheKeySizeList = null;
    }

    public Boolean getIsSSL2CompatibleClientHello() {
        return isSSL2CompatibleClientHello;
    }

    public void setIsSSL2CompatibleClientHello(Boolean isSSL2CompatibleClientHello) {
        this.isSSL2CompatibleClientHello = isSSL2CompatibleClientHello;
    }

    public byte[] getInitialBytes() {
        return initialBytes;
    }

    public void setInitialBytes(byte[] initialBytes) {
        this.initialBytes = initialBytes;
    }

    public String getType() {
        return type;
    }

    public String getVersion() {
        return version;
    }

    public void setDefaultVersion(Boolean defaultVersion) {
        this.defaultVersion = defaultVersion;
    }

    public Boolean isDefaultVersion() {
        return defaultVersion;
    }

    public void setConfig(Config config) {
        this.config = config;
    }

    public Config getConfig() {
        return config;
    }

    public void setTrace(WorkflowTrace trace) {
        this.trace = trace;
    }

    public WorkflowTrace getTrace() {
        return trace;
    }

    public void setSupportedVersionList(List<ProtocolVersion> supportedVersionList) {
        this.supportedVersionList = supportedVersionList;
    }

    public List<ProtocolVersion> getSupportedVersionList() {
        return supportedVersionList;
    }

    public void setVersionAcceptForbiddenCipherSuiteList(List<ProtocolVersion> versionAcceptForbiddenCipherSuiteList) {
        this.versionAcceptForbiddenCipherSuiteList = versionAcceptForbiddenCipherSuiteList;
    }

    public List<ProtocolVersion> getVersionAcceptForbiddenCipherSuiteList() {
        return versionAcceptForbiddenCipherSuiteList;
    }

    public void setSupportedRsaKeySizeList(List<Integer> supportedRsaKeySizeList) {
        this.supportedRsaKeySizeList = supportedRsaKeySizeList;
    }

    public List<Integer> getSupportedRsaKeySizeList() {
        return supportedRsaKeySizeList;
    }

    public void setSupportedDheKeySizeList(List<Integer> supportedDheKeySizeList) {
        this.supportedDheKeySizeList = supportedDheKeySizeList;
    }

    public List<Integer> getSupportedDheKeySizeList() {
        return supportedDheKeySizeList;
    }

    public ClientHelloMessage createClientHello() {
        ClientHelloMessage hello = new ClientHelloMessage(config);
        hello.setExtensions(
            ((ClientHelloMessage) trace.getLastReceivingAction().getReceivedMessages().get(0)).getExtensions());
        State s = new State(config);
        s.getTlsContext().setRecordLayer(new TlsRecordLayer(s.getTlsContext()));
        SendMessageHelper.prepareMessage(hello, s.getTlsContext());
        return hello;
    }

}
