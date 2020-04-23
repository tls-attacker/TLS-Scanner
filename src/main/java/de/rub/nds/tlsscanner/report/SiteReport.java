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
import de.rub.nds.tlsscanner.probe.invalidCurve.InvalidCurveResponse;
import de.rub.nds.tlsscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.report.after.statistic.nondeterminism.NonDetermnisimEvaluationReport;
import de.rub.nds.tlsscanner.report.after.prime.CommonDhValues;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.bleichenbacher.BleichenbacherTestResult;
import de.rub.nds.tlsscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.probe.directRaccoon.DirectRaccoonCipherSuiteFingerprint;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleCipherSuiteFingerprint;
import de.rub.nds.tlsscanner.report.result.raccoonattack.RaccoonAttackProbabilities;
import de.rub.nds.tlsscanner.report.result.statistics.RandomEvaluationResult;
import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Observable;
import java.util.Set;

public class SiteReport extends Observable implements Serializable {

    private final HashMap<String, TestResult> resultMap;

    // General
    private List<PerformanceData> performanceList;

    private final String host;

    private Boolean serverIsAlive = null;
    private Boolean supportsSslTls = null;

    // Attacks
    private List<BleichenbacherTestResult> bleichenbacherTestResultList;
    private List<PaddingOracleCipherSuiteFingerprint> paddingOracleTestResultList;
    private List<PaddingOracleCipherSuiteFingerprint> paddingOracleShakyEvalResultList;
    private KnownPaddingOracleVulnerability knownVulnerability = null;
    private NonDetermnisimEvaluationReport paddingOracleShakyReport = null;
    private List<DirectRaccoonCipherSuiteFingerprint> directRaccoonTestResultList;
    private List<InvalidCurveResponse> invalidCurveResultList;
    private List<RaccoonAttackProbabilities> raccoonAttackProbabilities;

    // Version
    private List<ProtocolVersion> versions = null;

    // Extensions
    private List<ExtensionType> supportedExtensions = null;
    private List<NamedGroup> supportedNamedGroups = null;
    private List<NamedGroup> supportedTls13Groups = null;
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms = null;
    private List<TokenBindingVersion> supportedTokenBindingVersion = null;
    private List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters = null;

    // Compression
    private List<CompressionMethod> supportedCompressionMethods = null;

    // RFC
    private CheckPattern macCheckPatterAppData = null;
    private CheckPattern macCheckPatternFinished = null;
    private CheckPattern verifyCheckPattern = null;

    // Certificate
    private CertificateChain certificateChain;

    // Ciphers
    private List<VersionSuiteListPair> versionSuitePairs = null;
    private Set<CipherSuite> cipherSuites = null;
    private List<CipherSuite> supportedTls13CipherSuites = null;

    // Session
    private Long sessionTicketLengthHint = null;

    // Renegotiation + SCSV
    // GCM Nonces
    private GcmPattern gcmPattern = null;

    // HTTPS Header
    private List<HttpsHeader> headerList = null;
    private Long hstsMaxAge = null;
    private Integer hpkpMaxAge = null;
    private List<HpkpPin> normalHpkpPins;
    private List<HpkpPin> reportOnlyHpkpPins;

    // Randomness
    private Map<TrackableValueType, ExtractedValueContainer> extractedValueContainerMap;
    private RandomEvaluationResult randomEvaluationResult;

    // PublicKey Params
    private Set<CommonDhValues> usedCommonDhValueList = null;
    private Integer weakestDhStrength = null;

    // Handshake Simulation
    private Integer handshakeSuccessfulCounter = null;
    private Integer handshakeFailedCounter = null;
    private Integer connectionRfc7918SecureCounter = null;
    private Integer connectionInsecureCounter = null;
    private List<SimulatedClientResult> simulatedClientList = null;

    private List<ProbeType> probeTypeList;

    private int performedTcpConnections = 0;

    public SiteReport(String host, List<ProbeType> probeTypeList) {
        this.host = host;
        this.probeTypeList = probeTypeList;
        performanceList = new LinkedList<>();
        extractedValueContainerMap = new HashMap<>();
        resultMap = new HashMap<>();
    }

    public synchronized Long getSessionTicketLengthHint() {
        return sessionTicketLengthHint;
    }

    public synchronized void setSessionTicketLengthHint(Long sessionTicketLengthHint) {
        this.sessionTicketLengthHint = sessionTicketLengthHint;
    }

    public synchronized int getPerformedTcpConnections() {
        return performedTcpConnections;
    }

    public synchronized void setPerformedTcpConnections(int performedTcpConnections) {
        this.performedTcpConnections = performedTcpConnections;
    }

    public synchronized HashMap<String, TestResult> getResultMap() {
        return resultMap;
    }

    public synchronized TestResult getResult(AnalyzedProperty property) {
        return getResult(property.toString());
    }

    public synchronized void removeResult(AnalyzedProperty property) {
        resultMap.remove(property.toString());
    }

    public synchronized TestResult getResult(String property) {
        TestResult result = resultMap.get(property);
        return (result == null) ? TestResult.NOT_TESTED_YET : result;
    }

    public synchronized void putResult(AnalyzedProperty property, TestResult result) {
        resultMap.put(property.toString(), result);
    }

    public synchronized void putResult(AnalyzedProperty property, Boolean result) {
        this.putResult(property,
                Objects.equals(result, Boolean.TRUE) ? TestResult.TRUE
                        : Objects.equals(result, Boolean.FALSE) ? TestResult.FALSE : TestResult.UNCERTAIN);
    }

    public synchronized void putResult(DrownVulnerabilityType result) {
        // todo: divide DROWN to several vulnerabilities ???
        if (result != null) {
            switch (result) {
                case NONE:
                    putResult(AnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN, false);
                    break;
                case UNKNOWN:
                    resultMap.put(AnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN.toString(), TestResult.UNCERTAIN);
                    break;
                default:
                    putResult(AnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN, TestResult.TRUE);
            }
        }
    }

    public synchronized void putResult(EarlyCcsVulnerabilityType result) {
        // todo: divide EARLY CCS to several vulnerabilities ???
        // also: EarlyFinishedVulnerabilityType
        if (result != null) {
            switch (result) {
                case NOT_VULNERABLE:
                    putResult(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS, false);
                    break;
                case UNKNOWN:
                    resultMap.put(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS.toString(), TestResult.UNCERTAIN);
                    break;
                default:
                    putResult(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS, true);
            }
        } else {
            resultMap.put(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS.toString(), TestResult.COULD_NOT_TEST);
        }
    }

    public synchronized void markAsChangedAndNotify() {
        this.hasChanged();
        this.notifyObservers();
    }

    public NonDetermnisimEvaluationReport getPaddingOracleShakyReport() {
        return paddingOracleShakyReport;
    }

    public void setPaddingOracleShakyReport(NonDetermnisimEvaluationReport paddingOracleShakyReport) {
        this.paddingOracleShakyReport = paddingOracleShakyReport;
    }

    public synchronized String getHost() {
        return host;
    }

    public synchronized List<ProbeType> getProbeTypeList() {
        return probeTypeList;
    }

    public synchronized Boolean getServerIsAlive() {
        return serverIsAlive;
    }

    public synchronized void setServerIsAlive(Boolean serverIsAlive) {
        this.serverIsAlive = serverIsAlive;
    }

    public synchronized List<TokenBindingVersion> getSupportedTokenBindingVersion() {
        return supportedTokenBindingVersion;
    }

    public synchronized void setSupportedTokenBindingVersion(List<TokenBindingVersion> supportedTokenBindingVersion) {
        this.supportedTokenBindingVersion = supportedTokenBindingVersion;
    }

    public synchronized List<TokenBindingKeyParameters> getSupportedTokenBindingKeyParameters() {
        return supportedTokenBindingKeyParameters;
    }

    public synchronized void setSupportedTokenBindingKeyParameters(
            List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters) {
        this.supportedTokenBindingKeyParameters = supportedTokenBindingKeyParameters;
    }

    public synchronized CertificateChain getCertificateChain() {
        return certificateChain;
    }

    public synchronized void setCertificateChain(CertificateChain certificateChain) {
        this.certificateChain = certificateChain;
    }

    public synchronized List<ProtocolVersion> getVersions() {
        return versions;
    }

    public synchronized void setVersions(List<ProtocolVersion> versions) {
        this.versions = versions;
    }

    public synchronized Set<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public synchronized void setCipherSuites(Set<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public synchronized List<CipherSuite> getSupportedTls13CipherSuites() {
        return supportedTls13CipherSuites;
    }

    public synchronized void setSupportedTls13CipherSuites(List<CipherSuite> supportedTls13CipherSuites) {
        this.supportedTls13CipherSuites = supportedTls13CipherSuites;
    }

    public synchronized List<NamedGroup> getSupportedNamedGroups() {
        return supportedNamedGroups;
    }

    public synchronized void setSupportedNamedGroups(List<NamedGroup> supportedNamedGroups) {
        this.supportedNamedGroups = supportedNamedGroups;
    }

    public synchronized List<NamedGroup> getSupportedTls13Groups() {
        return supportedTls13Groups;
    }

    public synchronized void setSupportedTls13Groups(List<NamedGroup> supportedTls13Groups) {
        this.supportedTls13Groups = supportedTls13Groups;
    }

    public synchronized List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        return supportedSignatureAndHashAlgorithms;
    }

    public synchronized void setSupportedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
        this.supportedSignatureAndHashAlgorithms = supportedSignatureAndHashAlgorithms;
    }

    public synchronized List<ExtensionType> getSupportedExtensions() {
        return supportedExtensions;
    }

    public synchronized void setSupportedExtensions(List<ExtensionType> supportedExtensions) {
        this.supportedExtensions = supportedExtensions;
    }

    public synchronized List<CompressionMethod> getSupportedCompressionMethods() {
        return supportedCompressionMethods;
    }

    public synchronized void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public synchronized CheckPattern getMacCheckPatternAppData() {
        return macCheckPatterAppData;
    }

    public synchronized void setMacCheckPatterAppData(CheckPattern macCheckPatterAppData) {
        this.macCheckPatterAppData = macCheckPatterAppData;
    }

    public synchronized CheckPattern getVerifyCheckPattern() {
        return verifyCheckPattern;
    }

    public synchronized void setVerifyCheckPattern(CheckPattern verifyCheckPattern) {
        this.verifyCheckPattern = verifyCheckPattern;
    }

    public synchronized Boolean getSupportsSslTls() {
        return supportsSslTls;
    }

    public synchronized void setSupportsSslTls(Boolean supportsSslTls) {
        this.supportsSslTls = supportsSslTls;
    }

    public synchronized GcmPattern getGcmPattern() {
        return gcmPattern;
    }

    public synchronized void setGcmPattern(GcmPattern gcmPattern) {
        this.gcmPattern = gcmPattern;
    }

    public synchronized List<VersionSuiteListPair> getVersionSuitePairs() {
        return versionSuitePairs;
    }

    public synchronized void setVersionSuitePairs(List<VersionSuiteListPair> versionSuitePairs) {
        this.versionSuitePairs = versionSuitePairs;
    }

    public synchronized Integer getHandshakeSuccessfulCounter() {
        return handshakeSuccessfulCounter;
    }

    public synchronized void setHandshakeSuccessfulCounter(Integer handshakeSuccessfulCounter) {
        this.handshakeSuccessfulCounter = handshakeSuccessfulCounter;
    }

    public synchronized Integer getHandshakeFailedCounter() {
        return handshakeFailedCounter;
    }

    public synchronized void setHandshakeFailedCounter(Integer handshakeFailedCounter) {
        this.handshakeFailedCounter = handshakeFailedCounter;
    }

    public synchronized Integer getConnectionRfc7918SecureCounter() {
        return connectionRfc7918SecureCounter;
    }

    public synchronized void setConnectionRfc7918SecureCounter(Integer connectionRfc7918SecureCounter) {
        this.connectionRfc7918SecureCounter = connectionRfc7918SecureCounter;
    }

    public synchronized Integer getConnectionInsecureCounter() {
        return connectionInsecureCounter;
    }

    public synchronized void setConnectionInsecureCounter(Integer connectionInsecureCounter) {
        this.connectionInsecureCounter = connectionInsecureCounter;
    }

    public synchronized List<SimulatedClientResult> getSimulatedClientList() {
        return simulatedClientList;
    }

    public synchronized void setSimulatedClientList(List<SimulatedClientResult> simulatedClientList) {
        this.simulatedClientList = simulatedClientList;
    }

    public synchronized String getFullReport(ScannerDetail detail, boolean printColorful) {
        return new SiteReportPrinter(this, detail, printColorful).getFullReport();
    }

    @Override
    public synchronized String toString() {
        return getFullReport(ScannerDetail.NORMAL, false);
    }

    public synchronized CheckPattern getMacCheckPatternFinished() {
        return macCheckPatternFinished;
    }

    public synchronized void setMacCheckPatternFinished(CheckPattern macCheckPatternFinished) {
        this.macCheckPatternFinished = macCheckPatternFinished;
    }

    public synchronized List<PerformanceData> getPerformanceList() {
        return performanceList;
    }

    public synchronized void setPerformanceList(List<PerformanceData> performanceList) {
        this.performanceList = performanceList;
    }

    public synchronized List<PaddingOracleCipherSuiteFingerprint> getPaddingOracleTestResultList() {
        return paddingOracleTestResultList;
    }

    public synchronized void setPaddingOracleTestResultList(
            List<PaddingOracleCipherSuiteFingerprint> paddingOracleTestResultList) {
        this.paddingOracleTestResultList = paddingOracleTestResultList;
    }

    public synchronized List<DirectRaccoonCipherSuiteFingerprint> getDirectRaccoonResultList() {
        return directRaccoonTestResultList;
    }

    public synchronized void setDirectRaccoonTestResultList(
            List<DirectRaccoonCipherSuiteFingerprint> directRaccoonTestResultList) {
        this.directRaccoonTestResultList = directRaccoonTestResultList;
    }

    public synchronized List<HttpsHeader> getHeaderList() {
        return headerList;
    }

    public synchronized void setHeaderList(List<HttpsHeader> headerList) {
        this.headerList = headerList;
    }

    public synchronized Long getHstsMaxAge() {
        return hstsMaxAge;
    }

    public synchronized void setHstsMaxAge(Long hstsMaxAge) {
        this.hstsMaxAge = hstsMaxAge;
    }

    public synchronized Integer getHpkpMaxAge() {
        return hpkpMaxAge;
    }

    public synchronized void setHpkpMaxAge(Integer hpkpMaxAge) {
        this.hpkpMaxAge = hpkpMaxAge;
    }

    public synchronized List<HpkpPin> getNormalHpkpPins() {
        return normalHpkpPins;
    }

    public synchronized void setNormalHpkpPins(List<HpkpPin> normalHpkpPins) {
        this.normalHpkpPins = normalHpkpPins;
    }

    public synchronized List<HpkpPin> getReportOnlyHpkpPins() {
        return reportOnlyHpkpPins;
    }

    public synchronized void setReportOnlyHpkpPins(List<HpkpPin> reportOnlyHpkpPins) {
        this.reportOnlyHpkpPins = reportOnlyHpkpPins;
    }

    public synchronized Map<TrackableValueType, ExtractedValueContainer> getExtractedValueContainerMap() {
        return extractedValueContainerMap;
    }

    public synchronized void setExtractedValueContainerList(
            Map<TrackableValueType, ExtractedValueContainer> extractedValueContainerMap) {
        this.extractedValueContainerMap = extractedValueContainerMap;
    }

    public synchronized RandomEvaluationResult getRandomEvaluationResult() {
        return randomEvaluationResult;
    }

    public synchronized void setRandomEvaluationResult(RandomEvaluationResult randomEvaluationResult) {
        this.randomEvaluationResult = randomEvaluationResult;
    }

    public synchronized Set<CommonDhValues> getUsedCommonDhValueList() {
        return usedCommonDhValueList;
    }

    public synchronized void setUsedCommonDhValueList(Set<CommonDhValues> usedCommonDhValueList) {
        this.usedCommonDhValueList = usedCommonDhValueList;
    }

    public synchronized Integer getWeakestDhStrength() {
        return weakestDhStrength;
    }

    public synchronized void setWeakestDhStrength(Integer weakestDhStrength) {
        this.weakestDhStrength = weakestDhStrength;
    }

    public synchronized List<BleichenbacherTestResult> getBleichenbacherTestResultList() {
        return bleichenbacherTestResultList;
    }

    public synchronized void setBleichenbacherTestResultList(List<BleichenbacherTestResult> bleichenbacherTestResultList) {
        this.bleichenbacherTestResultList = bleichenbacherTestResultList;
    }

    public synchronized KnownPaddingOracleVulnerability getKnownVulnerability() {
        return knownVulnerability;
    }

    public synchronized void setKnownVulnerability(KnownPaddingOracleVulnerability knownVulnerability) {
        this.knownVulnerability = knownVulnerability;
    }

    public synchronized List<PaddingOracleCipherSuiteFingerprint> getPaddingOracleShakyEvalResultList() {
        return paddingOracleShakyEvalResultList;
    }

    public synchronized void setPaddingOracleShakyEvalResultList(
            List<PaddingOracleCipherSuiteFingerprint> paddingOracleShakyEvalResultList) {
        this.paddingOracleShakyEvalResultList = paddingOracleShakyEvalResultList;
    }

    public synchronized List<InvalidCurveResponse> getInvalidCurveResultList() {
        return invalidCurveResultList;
    }

    public synchronized void setInvalidCurveResultList(List<InvalidCurveResponse> invalidCurveResultList) {
        this.invalidCurveResultList = invalidCurveResultList;
    }

    public synchronized List<RaccoonAttackProbabilities> getRaccoonAttackProbabilities() {
        return raccoonAttackProbabilities;
    }

    public synchronized void setRaccoonAttackProbabilities(List<RaccoonAttackProbabilities> raccoonAttackProbabilities) {
        this.raccoonAttackProbabilities = raccoonAttackProbabilities;
    }

}
