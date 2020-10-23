/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponse;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.serverscanner.constants.GcmPattern;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.vectorStatistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.leak.info.DirectRaccoonOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.leak.info.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.namedcurve.NamedCurveWitness;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakeSimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidCurve.InvalidCurveResponse;
import de.rub.nds.tlsscanner.serverscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.after.prime.CommonDhValues;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.report.result.bleichenbacher.BleichenbacherTestResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.cca.CcaTestResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.serverscanner.report.result.ocsp.OcspCertificateResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.raccoonattack.RaccoonAttackProbabilities;
import de.rub.nds.tlsscanner.serverscanner.report.result.statistics.RandomEvaluationResult;
import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Observable;
import java.util.Set;

public class SiteReport extends Observable implements Serializable {

    private final HashMap<String, TestResult> resultMap;

    private Set<ProbeType> executedProbes;

    // General
    private List<PerformanceData> performanceList;

    private final String host;

    private Boolean serverIsAlive = null;
    private Boolean supportsSslTls = null;

    // Attacks
    private List<BleichenbacherTestResult> bleichenbacherTestResultList;
    private List<InformationLeakTest<PaddingOracleTestInfo>> paddingOracleTestResultList;
    private KnownPaddingOracleVulnerability knownVulnerability = null;
    private List<InformationLeakTest<DirectRaccoonOracleTestInfo>> directRaccoonResultList;
    private List<InvalidCurveResponse> invalidCurveResultList;
    private List<RaccoonAttackProbabilities> raccoonAttackProbabilities;

    // Version
    private List<ProtocolVersion> versions = null;

    // Extensions
    private List<ExtensionType> supportedExtensions = null;
    private List<NamedGroup> supportedNamedGroups = null;
    private Map<NamedGroup, NamedCurveWitness> supportedNamedGroupsWitnesses;
    private Map<NamedGroup, NamedCurveWitness> supportedNamedGroupsWitnessesTls13;
    private List<NamedGroup> supportedTls13Groups = null;
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms = null;
    private List<TokenBindingVersion> supportedTokenBindingVersion = null;
    private List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters = null;

    // Compression
    private List<CompressionMethod> supportedCompressionMethods = null;

    // RFC
    private CheckPattern macCheckPatternAppData = null;
    private CheckPattern macCheckPatternFinished = null;
    private CheckPattern verifyCheckPattern = null;

    // Certificate
    private List<CertificateChain> certificateChainList;
    private List<NamedGroup> ecdsaPkGroupsStatic;
    private List<NamedGroup> ecdsaPkGroupsEphemeral;
    private List<NamedGroup> ecdsaPkGroupsTls13;
    private List<NamedGroup> ecdsaSigGroupsStatic;
    private List<NamedGroup> ecdsaSigGroupsEphemeral;
    private List<NamedGroup> ecdsaSigGroupsTls13;

    // OCSP
    private List<OcspCertificateResult> ocspResults;

    // Ciphers
    private List<VersionSuiteListPair> versionSuitePairs = null;
    private Set<CipherSuite> cipherSuites = null;

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
    private RandomEvaluationResult randomEvaluationResult = RandomEvaluationResult.NOT_ANALYZED;

    // PublicKey Params
    private Set<CommonDhValues> usedCommonDhValueList = null;
    private Integer weakestDhStrength = null;

    // Handshake Simulation
    private Integer handshakeSuccessfulCounter = null;
    private Integer handshakeFailedCounter = null;
    private Integer connectionRfc7918SecureCounter = null;
    private Integer connectionInsecureCounter = null;
    private List<SimulatedClientResult> simulatedClientList = null;

    // CCA
    private Boolean ccaSupported = null;
    private Boolean ccaRequired = null;
    private List<CcaTestResult> ccaTestResultList;

    private List<ProbeType> probeTypeList;

    private int performedTcpConnections = 0;

    public SiteReport() {
        resultMap = new HashMap<>();
        host = null;
    }

    public SiteReport(String host) {
        this.host = host;
        performanceList = new LinkedList<>();
        extractedValueContainerMap = new HashMap<>();
        resultMap = new HashMap<>();
        cipherSuites = new HashSet<>();
        versionSuitePairs = new LinkedList<>();
        executedProbes = new HashSet<>();
    }

    public synchronized boolean isProbeAlreadyExecuted(ProbeType type) {
        return (executedProbes.contains(type));
    }

    public synchronized void markProbeAsExecuted(ProbeType type) {
        executedProbes.add(type);
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

    public synchronized String getHost() {
        return host;
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

    public synchronized List<CertificateChain> getCertificateChainList() {
        return certificateChainList;
    }

    public synchronized void setCertificateChainList(List<CertificateChain> certificateChainList) {
        this.certificateChainList = certificateChainList;
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

    public synchronized void addCipherSuites(Set<CipherSuite> cipherSuites) {
        this.cipherSuites.addAll(cipherSuites);
    }

    public synchronized void setCipherSuites(Set<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
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
        return macCheckPatternAppData;
    }

    public synchronized void setMacCheckPatternAppData(CheckPattern macCheckPatternAppData) {
        this.macCheckPatternAppData = macCheckPatternAppData;
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

    public synchronized List<InformationLeakTest<PaddingOracleTestInfo>> getPaddingOracleTestResultList() {
        return paddingOracleTestResultList;
    }

    public synchronized void setPaddingOracleTestResultList(
            List<InformationLeakTest<PaddingOracleTestInfo>> paddingOracleTestResultList) {
        this.paddingOracleTestResultList = paddingOracleTestResultList;
    }

    public synchronized List<InformationLeakTest<DirectRaccoonOracleTestInfo>> getDirectRaccoonResultList() {
        return directRaccoonResultList;
    }

    public synchronized void setDirectRaccoonResultList(
            List<InformationLeakTest<DirectRaccoonOracleTestInfo>> directRaccoonResultList) {
        this.directRaccoonResultList = directRaccoonResultList;
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

    public synchronized Boolean getCcaSupported() {
        return this.getResult(AnalyzedProperty.SUPPORTS_CCA) == TestResult.TRUE;
    }

    public synchronized Boolean getCcaRequired() {
        return this.getResult(AnalyzedProperty.REQUIRES_CCA) == TestResult.TRUE;
    }

    public synchronized List<CcaTestResult> getCcaTestResultList() {
        return ccaTestResultList;
    }

    public synchronized void setCcaTestResultList(List<CcaTestResult> ccaTestResultList) {
        this.ccaTestResultList = ccaTestResultList;
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

    public synchronized List<NamedGroup> getEcdsaPkGroupsStatic() {
        return ecdsaPkGroupsStatic;
    }

    public synchronized void setEcdsaPkGroupsStatic(List<NamedGroup> ecdsaPkGroupsStatic) {
        this.ecdsaPkGroupsStatic = ecdsaPkGroupsStatic;
    }

    public synchronized List<NamedGroup> getEcdsaPkGroupsEphemeral() {
        return ecdsaPkGroupsEphemeral;
    }

    public synchronized void setEcdsaPkGroupsEphemeral(List<NamedGroup> ecdsaPkGroupsEphemeral) {
        this.ecdsaPkGroupsEphemeral = ecdsaPkGroupsEphemeral;
    }

    public synchronized Map<NamedGroup, NamedCurveWitness> getSupportedNamedGroupsWitnesses() {
        return supportedNamedGroupsWitnesses;
    }

    public synchronized void setSupportedNamedGroupsWitnesses(
            Map<NamedGroup, NamedCurveWitness> supportedNamedGroupsWitnesses) {
        this.supportedNamedGroupsWitnesses = supportedNamedGroupsWitnesses;
    }

    public synchronized List<NamedGroup> getEcdsaSigGroupsStatic() {
        return ecdsaSigGroupsStatic;
    }

    public synchronized void setEcdsaSigGroupsStatic(List<NamedGroup> ecdsaSigGroupsStatic) {
        this.ecdsaSigGroupsStatic = ecdsaSigGroupsStatic;
    }

    public synchronized List<NamedGroup> getEcdsaSigGroupsEphemeral() {
        return ecdsaSigGroupsEphemeral;
    }

    public synchronized void setEcdsaSigGroupsEphemeral(List<NamedGroup> ecdsaSigGroupsEphemeral) {
        this.ecdsaSigGroupsEphemeral = ecdsaSigGroupsEphemeral;
    }

    public synchronized List<NamedGroup> getEcdsaPkGroupsTls13() {
        return ecdsaPkGroupsTls13;
    }

    public synchronized void setEcdsaPkGroupsTls13(List<NamedGroup> ecdsaPkGroupsTls13) {
        this.ecdsaPkGroupsTls13 = ecdsaPkGroupsTls13;
    }

    public synchronized List<NamedGroup> getEcdsaSigGroupsTls13() {
        return ecdsaSigGroupsTls13;
    }

    public synchronized void setEcdsaSigGroupsTls13(List<NamedGroup> ecdsaSigGroupsTls13) {
        this.ecdsaSigGroupsTls13 = ecdsaSigGroupsTls13;
    }

    public synchronized Map<NamedGroup, NamedCurveWitness> getSupportedNamedGroupsWitnessesTls13() {
        return supportedNamedGroupsWitnessesTls13;
    }

    public synchronized void setSupportedNamedGroupsWitnessesTls13(
            Map<NamedGroup, NamedCurveWitness> supportedNamedGroupsWitnessesTls13) {
        this.supportedNamedGroupsWitnessesTls13 = supportedNamedGroupsWitnessesTls13;
    }

    public synchronized List<OcspCertificateResult> getOcspResults() {
        return ocspResults;
    }

    public synchronized void setOcspResults(List<OcspCertificateResult> ocspResults) {
        this.ocspResults = ocspResults;
    }
}
