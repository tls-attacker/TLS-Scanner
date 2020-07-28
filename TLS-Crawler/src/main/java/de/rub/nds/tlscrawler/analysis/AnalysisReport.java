/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.analysis;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import java.util.Map;

/**
 *
 * @author robert
 */
public class AnalysisReport {

    private long numberOfServersTotal;

    private long serversAlive;
    private long supportSslTls;

    private Map<ProtocolVersion, Map<CipherSuite, Long>> versionSuiteMap;
    private Map<CipherSuite, Long> cipherMap;
    private Map<ProtocolVersion, Long> versionMap;
    private Map<CompressionMethod, Long> compressionMethodMap;
    private Map<ProtocolVersion, Long> protocolVersionMap;
    private Map<AnalyzedProperty,Map<TestResult, Long>> analyzedPropertyMap;

    private Map<KnownPaddingOracleVulnerability, Long> knownPaddingOracleMap;

    public AnalysisReport() {
    }

    public long getNumberOfServersTotal() {
        return numberOfServersTotal;
    }

    public void setNumberOfServersTotal(long numberOfServersTotal) {
        this.numberOfServersTotal = numberOfServersTotal;
    }

    public long getServersAlive() {
        return serversAlive;
    }

    public void setServersAlive(long serversAlive) {
        this.serversAlive = serversAlive;
    }

    public long getSupportSslTls() {
        return supportSslTls;
    }

    public void setSupportSslTls(long supportSslTls) {
        this.supportSslTls = supportSslTls;
    }

    public Map<ProtocolVersion, Map<CipherSuite, Long>> getVersionSuiteMap() {
        return versionSuiteMap;
    }

    public void setVersionSuiteMap(Map<ProtocolVersion, Map<CipherSuite, Long>> versionSuiteMap) {
        this.versionSuiteMap = versionSuiteMap;
    }

    public Map<CipherSuite, Long> getCipherMap() {
        return cipherMap;
    }

    public void setCipherMap(Map<CipherSuite, Long> cipherMap) {
        this.cipherMap = cipherMap;
    }

    public Map<ProtocolVersion, Long> getVersionMap() {
        return versionMap;
    }

    public void setVersionMap(Map<ProtocolVersion, Long> versionMap) {
        this.versionMap = versionMap;
    }

    public Map<CompressionMethod, Long> getCompressionMethodMap() {
        return compressionMethodMap;
    }

    public void setCompressionMethodMap(Map<CompressionMethod, Long> compressionMethodMap) {
        this.compressionMethodMap = compressionMethodMap;
    }

    public Map<ProtocolVersion, Long> getProtocolVersionMap() {
        return protocolVersionMap;
    }

    public void setProtocolVersionMap(Map<ProtocolVersion, Long> protocolVersionMap) {
        this.protocolVersionMap = protocolVersionMap;
    }

    public Map<KnownPaddingOracleVulnerability, Long> getKnownPaddingOracleMap() {
        return knownPaddingOracleMap;
    }

    public void setKnownPaddingOracleMap(Map<KnownPaddingOracleVulnerability, Long> knownPaddingOracleMap) {
        this.knownPaddingOracleMap = knownPaddingOracleMap;
    }
    
    

}
