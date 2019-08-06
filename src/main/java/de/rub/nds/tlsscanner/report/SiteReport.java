/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.constants.GcmPattern;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.report.after.prime.CommonDhValues;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.bleichenbacher.BleichenbacherTestResult;
import de.rub.nds.tlsscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleCipherSuiteFingerprint;
import de.rub.nds.tlsscanner.report.result.statistics.RandomEvaluationResult;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.bouncycastle.crypto.tls.Certificate;

public class SiteReport {

    private final HashMap<String, TestResult> resultMap;
    
    //General
    private final List<ProbeType> probeTypeList;
    private List<PerformanceData> performanceList;

    private final String host;
    // TODO: Add to hashmap? 
    private Boolean serverIsAlive = null;
    private Boolean supportsSslTls = null;

    //Quirks

    //Attacks
    private List<BleichenbacherTestResult> bleichenbacherTestResultList;
    private List<PaddingOracleCipherSuiteFingerprint> paddingOracleTestResultList;
    private List<PaddingOracleCipherSuiteFingerprint> paddingOracleShakyEvalResultList;
    private KnownPaddingOracleVulnerability knownVulnerability = null;
    
    //Version
    private List<ProtocolVersion> versions = null;

    //Extensions
    private List<ExtensionType> supportedExtensions = null;
    private List<NamedGroup> supportedNamedGroups = null;
    private List<NamedGroup> supportedTls13Groups = null;
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms = null;
    private List<TokenBindingVersion> supportedTokenBindingVersion = null;
    private List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters = null;

    //Compression
    private List<CompressionMethod> supportedCompressionMethods = null;

    //RFC
    private CheckPattern macCheckPatterAppData = null;
    private CheckPattern macCheckPatternFinished = null;
    private CheckPattern verifyCheckPattern = null;

    //Certificate
    private Certificate certificate = null;
    private CertificateChain certificateChain;
    // TODO: Add to hashmap?
    private Boolean certificateExpired = null;
    private Boolean certificateNotYetValid = null;
    private Boolean certificateHasWeakHashAlgorithm = null;
    private Boolean certificateHasWeakSignAlgorithm = null;
    private Boolean certificateMachtesDomainName = null;
    private Boolean certificateIsTrusted = null;
    private Boolean certificateKeyIsBlacklisted = null;

    //Ciphers
    private List<VersionSuiteListPair> versionSuitePairs = null;
    private Set<CipherSuite> cipherSuites = null;
    private List<CipherSuite> supportedTls13CipherSuites = null;

    //Session
    private Long sessionTicketLengthHint = null;

    //Renegotiation + SCSV

    //GCM Nonces
    private GcmPattern gcmPattern = null;

    //HTTPS Header
    private List<HttpsHeader> headerList = null;
    private Long hstsMaxAge = null;
    private Integer hpkpMaxAge = null;
    private List<HpkpPin> normalHpkpPins;
    private List<HpkpPin> reportOnlyHpkpPins;

    //Randomness
    private List<ExtractedValueContainer> extractedValueContainerList;
    private RandomEvaluationResult randomEvaluationResult;

    //PublicKey Params
    private Set<CommonDhValues> usedCommonDhValueList = null;
    private Integer weakestDhStrength = null;

    //NoColor Flag
    private boolean noColor = false;

    //Handshake Simulation
    private Integer handshakeSuccessfulCounter = null;
    private Integer handshakeFailedCounter = null;
    private Integer connectionRfc7918SecureCounter = null;
    private Integer connectionInsecureCounter = null;
    private List<SimulatedClientResult> simulatedClientList = null;

    public SiteReport(String host, List<ProbeType> probeTypeList, boolean noColor) {
        this.host = host;
        this.probeTypeList = probeTypeList;
        this.noColor = noColor;
        performanceList = new LinkedList<>();
        extractedValueContainerList = new LinkedList<>();
        resultMap = new HashMap<>();
    }

    public HashMap<String, TestResult> getResultMap() {
        return resultMap;
    }
    
    public TestResult getResult(AnalyzedProperty property) {
        return getResult(property.toString());
    }
    
    public TestResult getResult(String property) {
        TestResult result = resultMap.get(property);
        return (result == null) ? TestResult.NOT_TESTED_YET : result;
    }
    
    public void putResult(AnalyzedProperty property, TestResult result) {
        resultMap.put(property.toString(), result);
    }
    
    public void putResult(AnalyzedProperty property, Boolean result) {
        if(result) {
            resultMap.put(property.toString(), TestResult.TRUE);
        } else {
            resultMap.put(property.toString(), TestResult.FALSE);
        }
    }
    
    public void putResult(DrownVulnerabilityType result) {
        // todo: divide DROWN to several vulnerabilities ???
        switch(result) {
            case NONE:
                putResult(AnalyzedProperty.VULNERABLE_TO_DROWN, false);
                break;
            case UNKNOWN:
                resultMap.put(AnalyzedProperty.VULNERABLE_TO_DROWN.toString(), TestResult.UNCERTAIN);
                break;
            default:
                putResult(AnalyzedProperty.VULNERABLE_TO_DROWN, TestResult.TRUE);
        }
    }
    
    public void putResult(EarlyCcsVulnerabilityType result) {
        // todo: divide EARLY CCS to several vulnerabilities ???
        // also: EarlyFinishedVulnerabilityType
        switch(result) {
            case NOT_VULNERABLE:
                putResult(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS, false);
                break;
            case UNKNOWN:
                resultMap.put(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS.toString(), TestResult.UNCERTAIN);
                break;
            default:
                putResult(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS, true);
        }
    }

    public String getHost() {
        return host;
    }

    public List<ProbeType> getProbeTypeList() {
        return probeTypeList;
    }

    public boolean isNoColor() {
        return noColor;
    }

    public Boolean getServerIsAlive() {
        return serverIsAlive;
    }

    public void setServerIsAlive(Boolean serverIsAlive) {
        this.serverIsAlive = serverIsAlive;
    }

    public List<TokenBindingVersion> getSupportedTokenBindingVersion() {
        return supportedTokenBindingVersion;
    }

    public void setSupportedTokenBindingVersion(List<TokenBindingVersion> supportedTokenBindingVersion) {
        this.supportedTokenBindingVersion = supportedTokenBindingVersion;
    }

    public List<TokenBindingKeyParameters> getSupportedTokenBindingKeyParameters() {
        return supportedTokenBindingKeyParameters;
    }

    public void setSupportedTokenBindingKeyParameters(List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters) {
        this.supportedTokenBindingKeyParameters = supportedTokenBindingKeyParameters;
    }

    public CertificateChain getCertificateChain() {
        return certificateChain;
    }

    public void setCertificateChain(CertificateChain certificateChain) {
        this.certificateChain = certificateChain;
    }

    public List<ProtocolVersion> getVersions() {
        return versions;
    }

    public void setVersions(List<ProtocolVersion> versions) {
        this.versions = versions;
    }

    public Set<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(Set<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public List<CipherSuite> getSupportedTls13CipherSuites() {
        return supportedTls13CipherSuites;
    }

    public void setSupportedTls13CipherSuites(List<CipherSuite> supportedTls13CipherSuites) {
        this.supportedTls13CipherSuites = supportedTls13CipherSuites;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public List<NamedGroup> getSupportedNamedGroups() {
        return supportedNamedGroups;
    }

    public void setSupportedNamedGroups(List<NamedGroup> supportedNamedGroups) {
        this.supportedNamedGroups = supportedNamedGroups;
    }

    public List<NamedGroup> getSupportedTls13Groups() {
        return supportedTls13Groups;
    }

    public void setSupportedTls13Groups(List<NamedGroup> supportedTls13Groups) {
        this.supportedTls13Groups = supportedTls13Groups;
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        return supportedSignatureAndHashAlgorithms;
    }

    public void setSupportedSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
        this.supportedSignatureAndHashAlgorithms = supportedSignatureAndHashAlgorithms;
    }

    public List<ExtensionType> getSupportedExtensions() {
        return supportedExtensions;
    }

    public void setSupportedExtensions(List<ExtensionType> supportedExtensions) {
        this.supportedExtensions = supportedExtensions;
    }

    public List<CompressionMethod> getSupportedCompressionMethods() {
        return supportedCompressionMethods;
    }

    public void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public CheckPattern getMacCheckPatternAppData() {
        return macCheckPatterAppData;
    }

    public void setMacCheckPatterAppData(CheckPattern macCheckPatterAppData) {
        this.macCheckPatterAppData = macCheckPatterAppData;
    }

    public CheckPattern getVerifyCheckPattern() {
        return verifyCheckPattern;
    }

    public void setVerifyCheckPattern(CheckPattern verifyCheckPattern) {
        this.verifyCheckPattern = verifyCheckPattern;
    }

    public Boolean getSupportsSslTls() {
        return supportsSslTls;
    }

    public void setSupportsSslTls(Boolean supportsSslTls) {
        this.supportsSslTls = supportsSslTls;
    }

    public Boolean getCertificateExpired() {
        return certificateExpired;
    }

    public void setCertificateExpired(Boolean certificateExpired) {
        this.certificateExpired = certificateExpired;
    }

    public Boolean getCertificateNotYetValid() {
        return certificateNotYetValid;
    }

    public void setCertificateNotYetValid(Boolean certificateNotYetValid) {
        this.certificateNotYetValid = certificateNotYetValid;
    }

    public Boolean getCertificateHasWeakHashAlgorithm() {
        return certificateHasWeakHashAlgorithm;
    }

    public void setCertificateHasWeakHashAlgorithm(Boolean certificateHasWeakHashAlgorithm) {
        this.certificateHasWeakHashAlgorithm = certificateHasWeakHashAlgorithm;
    }

    public Boolean getCertificateHasWeakSignAlgorithm() {
        return certificateHasWeakSignAlgorithm;
    }

    public void setCertificateHasWeakSignAlgorithm(Boolean certificateHasWeakSignAlgorithm) {
        this.certificateHasWeakSignAlgorithm = certificateHasWeakSignAlgorithm;
    }

    public Boolean getCertificateMachtesDomainName() {
        return certificateMachtesDomainName;
    }

    public void setCertificateMachtesDomainName(Boolean certificateMachtesDomainName) {
        this.certificateMachtesDomainName = certificateMachtesDomainName;
    }

    public Boolean getCertificateIsTrusted() {
        return certificateIsTrusted;
    }

    public void setCertificateIsTrusted(Boolean certificateIsTrusted) {
        this.certificateIsTrusted = certificateIsTrusted;
    }

    public Boolean getCertificateKeyIsBlacklisted() {
        return certificateKeyIsBlacklisted;
    }

    public void setCertificateKeyIsBlacklisted(Boolean certificateKeyIsBlacklisted) {
        this.certificateKeyIsBlacklisted = certificateKeyIsBlacklisted;
    }

    public GcmPattern getGcmPattern() {
        return gcmPattern;
    }

    public void setGcmPattern(GcmPattern gcmPattern) {
        this.gcmPattern = gcmPattern;
    }

    public List<VersionSuiteListPair> getVersionSuitePairs() {
        return versionSuitePairs;
    }

    public void setVersionSuitePairs(List<VersionSuiteListPair> versionSuitePairs) {
        this.versionSuitePairs = versionSuitePairs;
    }

    public Integer getHandshakeSuccessfulCounter() {
        return handshakeSuccessfulCounter;
    }

    public void setHandshakeSuccessfulCounter(Integer handshakeSuccessfulCounter) {
        this.handshakeSuccessfulCounter = handshakeSuccessfulCounter;
    }

    public Integer getHandshakeFailedCounter() {
        return handshakeFailedCounter;
    }

    public void setHandshakeFailedCounter(Integer handshakeFailedCounter) {
        this.handshakeFailedCounter = handshakeFailedCounter;
    }

    public Integer getConnectionRfc7918SecureCounter() {
        return connectionRfc7918SecureCounter;
    }

    public void setConnectionRfc7918SecureCounter(Integer connectionRfc7918SecureCounter) {
        this.connectionRfc7918SecureCounter = connectionRfc7918SecureCounter;
    }

    public Integer getConnectionInsecureCounter() {
        return connectionInsecureCounter;
    }

    public void setConnectionInsecureCounter(Integer connectionInsecureCounter) {
        this.connectionInsecureCounter = connectionInsecureCounter;
    }

    public List<SimulatedClientResult> getSimulatedClientList() {
        return simulatedClientList;
    }

    public void setSimulatedClientList(List<SimulatedClientResult> simulatedClientList) {
        this.simulatedClientList = simulatedClientList;
    }

    public String getFullReport(ScannerDetail detail) {
        return new SiteReportPrinter(this, detail).getFullReport();
    }

    @Override
    public String toString() {
        return getFullReport(ScannerDetail.NORMAL);
    }

    public CheckPattern getMacCheckPatternFinished() {
        return macCheckPatternFinished;
    }

    public void setMacCheckPatternFinished(CheckPattern macCheckPatternFinished) {
        this.macCheckPatternFinished = macCheckPatternFinished;
    }

    public List<PerformanceData> getPerformanceList() {
        return performanceList;
    }

    public void setPerformanceList(List<PerformanceData> performanceList) {
        this.performanceList = performanceList;
    }

    public List<PaddingOracleCipherSuiteFingerprint> getPaddingOracleTestResultList() {
        return paddingOracleTestResultList;
    }

    public void setPaddingOracleTestResultList(List<PaddingOracleCipherSuiteFingerprint> paddingOracleTestResultList) {
        this.paddingOracleTestResultList = paddingOracleTestResultList;
    }

    public List<HttpsHeader> getHeaderList() {
        return headerList;
    }

    public void setHeaderList(List<HttpsHeader> headerList) {
        this.headerList = headerList;
    }

    public Long getHstsMaxAge() {
        return hstsMaxAge;
    }

    public void setHstsMaxAge(Long hstsMaxAge) {
        this.hstsMaxAge = hstsMaxAge;
    }

    public Integer getHpkpMaxAge() {
        return hpkpMaxAge;
    }

    public void setHpkpMaxAge(Integer hpkpMaxAge) {
        this.hpkpMaxAge = hpkpMaxAge;
    }

    public List<HpkpPin> getNormalHpkpPins() {
        return normalHpkpPins;
    }

    public void setNormalHpkpPins(List<HpkpPin> normalHpkpPins) {
        this.normalHpkpPins = normalHpkpPins;
    }

    public List<HpkpPin> getReportOnlyHpkpPins() {
        return reportOnlyHpkpPins;
    }

    public void setReportOnlyHpkpPins(List<HpkpPin> reportOnlyHpkpPins) {
        this.reportOnlyHpkpPins = reportOnlyHpkpPins;
    }

    public List<ExtractedValueContainer> getExtractedValueContainerList() {
        return extractedValueContainerList;
    }

    public void setExtractedValueContainerList(List<ExtractedValueContainer> extractedValueContainerList) {
        this.extractedValueContainerList = extractedValueContainerList;
    }

    public RandomEvaluationResult getRandomEvaluationResult() {
        return randomEvaluationResult;
    }

    public void setRandomEvaluationResult(RandomEvaluationResult randomEvaluationResult) {
        this.randomEvaluationResult = randomEvaluationResult;
    }

    public Set<CommonDhValues> getUsedCommonDhValueList() {
        return usedCommonDhValueList;
    }

    public void setUsedCommonDhValueList(Set<CommonDhValues> usedCommonDhValueList) {
        this.usedCommonDhValueList = usedCommonDhValueList;
    }

    public Integer getWeakestDhStrength() {
        return weakestDhStrength;
    }

    public void setWeakestDhStrength(Integer weakestDhStrength) {
        this.weakestDhStrength = weakestDhStrength;
    }

    public List<BleichenbacherTestResult> getBleichenbacherTestResultList() {
        return bleichenbacherTestResultList;
    }

    public void setBleichenbacherTestResultList(List<BleichenbacherTestResult> bleichenbacherTestResultList) {
        this.bleichenbacherTestResultList = bleichenbacherTestResultList;
    }

    public KnownPaddingOracleVulnerability getKnownVulnerability() {
        return knownVulnerability;
    }

    public void setKnownVulnerability(KnownPaddingOracleVulnerability knownVulnerability) {
        this.knownVulnerability = knownVulnerability;
    }

    public List<PaddingOracleCipherSuiteFingerprint> getPaddingOracleShakyEvalResultList() {
        return paddingOracleShakyEvalResultList;
    }

    public void setPaddingOracleShakyEvalResultList(List<PaddingOracleCipherSuiteFingerprint> paddingOracleShakyEvalResultList) {
        this.paddingOracleShakyEvalResultList = paddingOracleShakyEvalResultList;
    }
}
