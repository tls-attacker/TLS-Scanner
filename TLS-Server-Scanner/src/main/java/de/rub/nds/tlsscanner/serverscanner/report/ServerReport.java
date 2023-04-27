/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestampList;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.DefaultPrintingScheme;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.prime.CommonDhValues;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.constants.GcmPattern;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineReport;
import de.rub.nds.tlsscanner.serverscanner.leak.BleichenbacherOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.leak.DirectRaccoonOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.InvalidCurveResponse;
import de.rub.nds.tlsscanner.serverscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.serverscanner.probe.namedgroup.NamedGroupWitness;
import de.rub.nds.tlsscanner.serverscanner.probe.result.cca.CcaTestResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.serverscanner.probe.result.ocsp.OcspCertificateResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.quic.QuicConnectionMigrationResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.quic.QuicTls12HandshakeResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.quic.QuicVersionResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.raccoonattack.RaccoonAttackProbabilities;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ServerReport extends TlsScanReport {

    private final String host;
    private final Integer port;

    private Boolean serverIsAlive = null;
    private Boolean speaksProtocol = null;
    private Boolean isHandshaking = null;

    // Application
    private List<ApplicationProtocol> supportedApplications = null;

    // Attacks
    private List<InformationLeakTest<BleichenbacherOracleTestInfo>> bleichenbacherTestResultList;
    private List<InformationLeakTest<DirectRaccoonOracleTestInfo>> directRaccoonResultList;
    private List<InvalidCurveResponse> invalidCurveResultList;
    private List<RaccoonAttackProbabilities> raccoonAttackProbabilities;

    // Extensions
    private List<ExtensionType> supportedExtensions = null;
    private List<NamedGroup> supportedNamedGroups = null;
    private Map<NamedGroup, NamedGroupWitness> supportedNamedGroupsWitnesses;
    private Map<NamedGroup, NamedGroupWitness> supportedNamedGroupsWitnessesTls13;
    private List<NamedGroup> supportedTls13Groups = null;
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithmsCert = null;
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithmsSke = null;
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithmsTls13 = null;
    private List<TokenBindingVersion> supportedTokenBindingVersion = null;
    private List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters = null;

    private NamedGroup helloRetryRequestSelectedNamedGroup = null;

    // RFC
    private CheckPattern macCheckPatternAppData = null;
    private CheckPattern macCheckPatternFinished = null;
    private CheckPattern verifyCheckPattern = null;

    // Certificate
    private List<NamedGroup> ecdsaPkGroupsStatic;
    private List<NamedGroup> ecdsaPkGroupsEphemeral;
    private List<NamedGroup> ecdsaPkGroupsTls13;
    private List<NamedGroup> ecdsaSigGroupsStatic;
    private List<NamedGroup> ecdsaSigGroupsEphemeral;
    private List<NamedGroup> ecdsaSigGroupsTls13;
    private int minimumRsaCertKeySize;
    private int minimumDssCertKeySize;

    // OCSP
    private List<OcspCertificateResult> ocspResults;

    // Certificate Transparency
    private SignedCertificateTimestampList precertificateSctList = null;
    private SignedCertificateTimestampList handshakeSctList = null;
    private SignedCertificateTimestampList ocspSctList = null;

    // Session
    private Long sessionTicketLengthHint = null;

    // Renegotiation + SCSV
    // GCM Nonces
    private GcmPattern gcmPattern = null;

    // HTTPS Header
    private List<HttpHeader> headerList = null;
    private Long hstsMaxAge = null;
    private Integer hpkpMaxAge = null;
    private List<HpkpPin> normalHpkpPins;
    private List<HpkpPin> reportOnlyHpkpPins;

    // DTLS
    private Integer cookieLength = null;

    // QUIC
    private Boolean quicRetryRequired = null;
    private List<QuicVersionResult.Entry> supportedQuicVersions = null;
    private QuicTransportParameters quicTransportParameters = null;
    private QuicTls12HandshakeResult quicTls12HandshakeResult = null;
    private QuicConnectionMigrationResult quicConnectionMigrationResult = null;

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

    private Long closedAfterFinishedDelta;
    private Long closedAfterAppDataDelta;

    // Guidelines
    private List<GuidelineReport> guidelineReports = new ArrayList<>();

    private List<ProbeType> probeTypeList;

    private int performedTcpConnections = 0;

    // Rating
    private int score;
    private ScoreReport scoreReport;

    // Config profile used to limit our Client Hello
    private String configProfileIdentifier;
    private String configProfileIdentifierTls13;

    public ServerReport() {
        super();
        host = null;
        port = null;
    }

    public ServerReport(String host, int port) {
        super();
        this.host = host;
        this.port = port;
    }

    public synchronized List<ApplicationProtocol> getSupportedApplications() {
        return supportedApplications;
    }

    public synchronized void setSupportedApplications(
            List<ApplicationProtocol> supportedApplications) {
        this.supportedApplications = supportedApplications;
    }

    public synchronized Long getSessionTicketLengthHint() {
        return sessionTicketLengthHint;
    }

    public synchronized void setSessionTicketLengthHint(Long sessionTicketLengthHint) {
        this.sessionTicketLengthHint = sessionTicketLengthHint;
    }

    public synchronized String getHost() {
        return host;
    }

    public synchronized int getPort() {
        return port;
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

    public synchronized void setSupportedTokenBindingVersion(
            List<TokenBindingVersion> supportedTokenBindingVersion) {
        this.supportedTokenBindingVersion = supportedTokenBindingVersion;
    }

    public synchronized List<TokenBindingKeyParameters> getSupportedTokenBindingKeyParameters() {
        return supportedTokenBindingKeyParameters;
    }

    public synchronized void setSupportedTokenBindingKeyParameters(
            List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters) {
        this.supportedTokenBindingKeyParameters = supportedTokenBindingKeyParameters;
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
        HashSet<SignatureAndHashAlgorithm> combined = new HashSet<>();
        if (supportedSignatureAndHashAlgorithmsCert != null) {
            combined.addAll(supportedSignatureAndHashAlgorithmsCert);
        }
        if (supportedSignatureAndHashAlgorithmsSke != null) {
            combined.addAll(supportedSignatureAndHashAlgorithmsSke);
        }
        return new ArrayList<>(combined);
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsTls13() {
        return supportedSignatureAndHashAlgorithmsTls13;
    }

    public void setSupportedSignatureAndHashAlgorithmsTls13(
            List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithmsTls13) {
        this.supportedSignatureAndHashAlgorithmsTls13 = supportedSignatureAndHashAlgorithmsTls13;
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsCert() {
        return supportedSignatureAndHashAlgorithmsCert;
    }

    public synchronized void setSupportedSignatureAndHashAlgorithmsCert(
            List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
        this.supportedSignatureAndHashAlgorithmsCert = supportedSignatureAndHashAlgorithms;
    }

    public synchronized void setSupportedSignatureAndHashAlgorithmsSke(
            List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
        this.supportedSignatureAndHashAlgorithmsSke = supportedSignatureAndHashAlgorithms;
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsSke() {
        return supportedSignatureAndHashAlgorithmsSke;
    }

    public synchronized List<ExtensionType> getSupportedExtensions() {
        return supportedExtensions;
    }

    public synchronized void setSupportedExtensions(List<ExtensionType> supportedExtensions) {
        this.supportedExtensions = supportedExtensions;
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

    public synchronized Boolean getSpeaksProtocol() {
        return speaksProtocol;
    }

    public synchronized void setSpeaksProtocol(Boolean speaksProtocol) {
        this.speaksProtocol = speaksProtocol;
    }

    public Boolean getIsHandshaking() {
        return isHandshaking;
    }

    public void setIsHandshaking(Boolean isHandshaking) {
        this.isHandshaking = isHandshaking;
    }

    public synchronized Integer getCookieLength() {
        return cookieLength;
    }

    public synchronized void setCookieLength(Integer cookieLength) {
        this.cookieLength = cookieLength;
    }

    public synchronized GcmPattern getGcmPattern() {
        return gcmPattern;
    }

    public synchronized void setGcmPattern(GcmPattern gcmPattern) {
        this.gcmPattern = gcmPattern;
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

    public synchronized void setConnectionRfc7918SecureCounter(
            Integer connectionRfc7918SecureCounter) {
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

    public synchronized void setSimulatedClientList(
            List<SimulatedClientResult> simulatedClientList) {
        this.simulatedClientList = simulatedClientList;
    }

    @Override
    public synchronized String getFullReport(ScannerDetail detail, boolean printColorful) {
        return new ServerReportPrinter(
                        this,
                        detail,
                        DefaultPrintingScheme.getDefaultPrintingScheme(),
                        printColorful)
                .getFullReport();
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

    public synchronized List<InformationLeakTest<DirectRaccoonOracleTestInfo>>
            getDirectRaccoonResultList() {
        return directRaccoonResultList;
    }

    public synchronized void setDirectRaccoonResultList(
            List<InformationLeakTest<DirectRaccoonOracleTestInfo>> directRaccoonResultList) {
        this.directRaccoonResultList = directRaccoonResultList;
    }

    public synchronized List<HttpHeader> getHeaderList() {
        return headerList;
    }

    public synchronized void setHeaderList(List<HttpHeader> headerList) {
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

    public synchronized List<InformationLeakTest<BleichenbacherOracleTestInfo>>
            getBleichenbacherTestResultList() {
        return bleichenbacherTestResultList;
    }

    public synchronized void setBleichenbacherTestResultList(
            List<InformationLeakTest<BleichenbacherOracleTestInfo>> bleichenbacherTestResultList) {
        this.bleichenbacherTestResultList = bleichenbacherTestResultList;
    }

    public synchronized Boolean getCcaSupported() {
        return this.getResult(TlsAnalyzedProperty.SUPPORTS_CCA) == TestResults.TRUE;
    }

    public synchronized Boolean getCcaRequired() {
        return this.getResult(TlsAnalyzedProperty.REQUIRES_CCA) == TestResults.TRUE;
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

    public synchronized void setInvalidCurveResultList(
            List<InvalidCurveResponse> invalidCurveResultList) {
        this.invalidCurveResultList = invalidCurveResultList;
    }

    public synchronized List<RaccoonAttackProbabilities> getRaccoonAttackProbabilities() {
        return raccoonAttackProbabilities;
    }

    public synchronized void setRaccoonAttackProbabilities(
            List<RaccoonAttackProbabilities> raccoonAttackProbabilities) {
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

    public synchronized Map<NamedGroup, NamedGroupWitness> getSupportedNamedGroupsWitnesses() {
        return supportedNamedGroupsWitnesses;
    }

    public synchronized void setSupportedNamedGroupsWitnesses(
            Map<NamedGroup, NamedGroupWitness> supportedNamedGroupsWitnesses) {
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

    public synchronized Map<NamedGroup, NamedGroupWitness> getSupportedNamedGroupsWitnessesTls13() {
        return supportedNamedGroupsWitnessesTls13;
    }

    public synchronized void setSupportedNamedGroupsWitnessesTls13(
            Map<NamedGroup, NamedGroupWitness> supportedNamedGroupsWitnessesTls13) {
        this.supportedNamedGroupsWitnessesTls13 = supportedNamedGroupsWitnessesTls13;
    }

    public synchronized List<OcspCertificateResult> getOcspResults() {
        return ocspResults;
    }

    public synchronized void setOcspResults(List<OcspCertificateResult> ocspResults) {
        this.ocspResults = ocspResults;
    }

    public synchronized SignedCertificateTimestampList getPrecertificateSctList() {
        return precertificateSctList;
    }

    public synchronized void setPrecertificateSctList(
            SignedCertificateTimestampList precertificateSctList) {
        this.precertificateSctList = precertificateSctList;
    }

    public synchronized SignedCertificateTimestampList getHandshakeSctList() {
        return handshakeSctList;
    }

    public synchronized void setHandshakeSctList(SignedCertificateTimestampList handshakeSctList) {
        this.handshakeSctList = handshakeSctList;
    }

    public synchronized SignedCertificateTimestampList getOcspSctList() {
        return ocspSctList;
    }

    public synchronized void setOcspSctList(SignedCertificateTimestampList ocspSctList) {
        this.ocspSctList = ocspSctList;
    }

    public synchronized int getScore() {
        return score;
    }

    public synchronized void setScore(int score) {
        this.score = score;
    }

    public synchronized ScoreReport getScoreReport() {
        return scoreReport;
    }

    public synchronized void setScoreReport(ScoreReport scoreReport) {
        this.scoreReport = scoreReport;
    }

    public synchronized int getMinimumRsaCertKeySize() {
        return minimumRsaCertKeySize;
    }

    public synchronized void setMinimumRsaCertKeySize(int minimumRsaCertKeySize) {
        this.minimumRsaCertKeySize = minimumRsaCertKeySize;
    }

    public synchronized int getMinimumDssCertKeySize() {
        return minimumDssCertKeySize;
    }

    public synchronized void setMinimumDssCertKeySize(int minimumDssCertKeySize) {
        this.minimumDssCertKeySize = minimumDssCertKeySize;
    }

    public synchronized NamedGroup getHelloRetryRequestSelectedNamedGroup() {
        return helloRetryRequestSelectedNamedGroup;
    }

    public synchronized void setHelloRetryRequestSelectedNamedGroup(
            NamedGroup helloRetryRequestSelectedNamedGroup) {
        this.helloRetryRequestSelectedNamedGroup = helloRetryRequestSelectedNamedGroup;
    }

    public synchronized List<GuidelineReport> getGuidelineReports() {
        return guidelineReports;
    }

    public synchronized void setGuidelineReports(List<GuidelineReport> guidelineReports) {
        this.guidelineReports = guidelineReports;
    }

    public synchronized String getConfigProfileIdentifier() {
        return configProfileIdentifier;
    }

    public synchronized void setConfigProfileIdentifier(String configProfileIdentifier) {
        this.configProfileIdentifier = configProfileIdentifier;
    }

    public synchronized String getConfigProfileIdentifierTls13() {
        return configProfileIdentifierTls13;
    }

    public synchronized void setConfigProfileIdentifierTls13(String configProfileIdentifierTls13) {
        this.configProfileIdentifierTls13 = configProfileIdentifierTls13;
    }

    public synchronized Long getClosedAfterFinishedDelta() {
        return closedAfterFinishedDelta;
    }

    public synchronized void setClosedAfterFinishedDelta(long closedAfterFinishedDelta) {
        this.closedAfterFinishedDelta = closedAfterFinishedDelta;
    }

    public synchronized Long getClosedAfterAppDataDelta() {
        return closedAfterAppDataDelta;
    }

    public synchronized void setClosedAfterAppDataDelta(long closedAfterAppDataDelta) {
        this.closedAfterAppDataDelta = closedAfterAppDataDelta;
    }

    public Boolean getQuicRetryRequired() {
        return quicRetryRequired;
    }

    public void setQuicRetryRequired(Boolean quicRetryRequired) {
        this.quicRetryRequired = quicRetryRequired;
    }

    public synchronized List<QuicVersionResult.Entry> getSupportedQuicVersions() {
        return supportedQuicVersions;
    }

    public synchronized void setSupportedQuicVersions(
            List<QuicVersionResult.Entry> supportedQuicVersions) {
        this.supportedQuicVersions = supportedQuicVersions;
    }

    public synchronized QuicTransportParameters getQuicTransportParameters() {
        return quicTransportParameters;
    }

    public synchronized void setQuicTransportParameters(
            QuicTransportParameters quicTransportParameters) {
        this.quicTransportParameters = quicTransportParameters;
    }

    public synchronized QuicTls12HandshakeResult getQuicTls12HandshakeResult() {
        return quicTls12HandshakeResult;
    }

    public synchronized void setQuicTls12HandshakeResult(
            QuicTls12HandshakeResult quicTls12HandshakeResult) {
        this.quicTls12HandshakeResult = quicTls12HandshakeResult;
    }

    public QuicConnectionMigrationResult getQuicConnectionMigrationResult() {
        return quicConnectionMigrationResult;
    }

    public void setQuicConnectionMigrationResult(
            QuicConnectionMigrationResult quicConnectionMigrationResult) {
        this.quicConnectionMigrationResult = quicConnectionMigrationResult;
    }
}
