/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.scanner.core.probe.result.MapResult;
import de.rub.nds.scanner.core.probe.result.SetResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestampList;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.DefaultPrintingScheme;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.prime.CommonDhValues;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.constants.GcmPattern;
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
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ServerReport extends TlsScanReport {

    private final String host;
    private final Integer port;

    private Boolean serverIsAlive = null;
    private Boolean speaksProtocol = null;
    private Boolean isHandshaking = null;

    // Attacks
    private NamedGroup helloRetryRequestSelectedNamedGroup = null;

    // RFC
    private CheckPattern macCheckPatternAppData = null;
    private CheckPattern macCheckPatternFinished = null;
    private CheckPattern verifyCheckPattern = null;

    // Certificate
    private int minimumRsaCertKeySize;
    private int minimumDssCertKeySize;

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
    private Long hstsMaxAge = null;
    private Integer hpkpMaxAge = null; //

    // DTLS
    private Integer cookieLength = null;

    // QUIC
    private Boolean quicRetryRequired = null;
    private List<QuicVersionResult.Entry> supportedQuicVersions = null;
    private QuicTransportParameters quicTransportParameters = null;
    private QuicTls12HandshakeResult quicTls12HandshakeResult = null;
    private QuicConnectionMigrationResult quicConnectionMigrationResult = null;

    // PublicKey Params
    private Integer weakestDhStrength = null;

    // Handshake Simulation
    private Integer handshakeSuccessfulCounter = null;
    private Integer handshakeFailedCounter = null;
    private Integer connectionRfc7918SecureCounter = null;
    private Integer connectionInsecureCounter = null;

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

    @Override
    public synchronized String toString() {
        return new ServerReportPrinter(
                        this,
                        ScannerDetail.NORMAL,
                        DefaultPrintingScheme.getDefaultPrintingScheme(),
                        false)
                .getFullReport();
    }

    public synchronized CheckPattern getMacCheckPatternFinished() {
        return macCheckPatternFinished;
    }

    public synchronized void setMacCheckPatternFinished(CheckPattern macCheckPatternFinished) {
        this.macCheckPatternFinished = macCheckPatternFinished;
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

    public synchronized Integer getWeakestDhStrength() {
        return weakestDhStrength;
    }

    public synchronized void setWeakestDhStrength(Integer weakestDhStrength) {
        this.weakestDhStrength = weakestDhStrength;
    }

    public synchronized List<InvalidCurveResponse> getInvalidCurveTestResultList() {
        ListResult<InvalidCurveResponse> listResult =
                getListResult(
                        TlsAnalyzedProperty.INVALID_CURVE_TEST_RESULT, InvalidCurveResponse.class);
        return listResult == null ? null : listResult.getList();
    }

    // TODO when is this NOTTESTEDYET set???
    public synchronized List<RaccoonAttackProbabilities> getRaccoonAttackProbabilities() {
        if (getResult(TlsAnalyzedProperty.RACCOON_ATTACK_PROBABILITIES)
                == TestResults.NOT_TESTED_YET) {
            return null;
        }
        ListResult<RaccoonAttackProbabilities> listResult =
                getListResult(
                        TlsAnalyzedProperty.RACCOON_ATTACK_PROBABILITIES,
                        RaccoonAttackProbabilities.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<OcspCertificateResult> getOcspResults() {
        ListResult<OcspCertificateResult> listResult =
                getListResult(TlsAnalyzedProperty.OCSP_RESULTS, OcspCertificateResult.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<InformationLeakTest<DirectRaccoonOracleTestInfo>>
            getRaccoonTestResultList() {
        @SuppressWarnings("unchecked")
        ListResult<InformationLeakTest<DirectRaccoonOracleTestInfo>> listResult =
                (ListResult<InformationLeakTest<DirectRaccoonOracleTestInfo>>)
                        getListResult(TlsAnalyzedProperty.DIRECT_RACCOON_TEST_RESULT);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<InformationLeakTest<BleichenbacherOracleTestInfo>>
            getBleichenbacherTestResultList() {
        @SuppressWarnings("unchecked")
        ListResult<InformationLeakTest<BleichenbacherOracleTestInfo>> listResult =
                (ListResult<InformationLeakTest<BleichenbacherOracleTestInfo>>)
                        getListResult(TlsAnalyzedProperty.BLEICHENBACHER_TEST_RESULT);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<CcaTestResult> getCcaTestResultList() {
        ListResult<CcaTestResult> listResult =
                getListResult(TlsAnalyzedProperty.CCA_TEST_RESULTS, CcaTestResult.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<HpkpPin> getNormalHpkpPins() {
        ListResult<HpkpPin> listResult =
                getListResult(TlsAnalyzedProperty.NORMAL_HPKP_PINS, HpkpPin.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<HpkpPin> getReportOnlyHpkpPins() {
        ListResult<HpkpPin> listResult =
                getListResult(TlsAnalyzedProperty.REPORT_ONLY_HPKP_PINS, HpkpPin.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<SimulatedClientResult> getSimulatedClientsResultList() {
        ListResult<SimulatedClientResult> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_SIMULATION_RESULTS, SimulatedClientResult.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<ApplicationProtocol> getSupportedApplicationProtocols() {
        ListResult<ApplicationProtocol> listResult =
                (ListResult<ApplicationProtocol>)
                        getListResult(
                                TlsAnalyzedProperty.SUPPORTED_APPLICATIONS,
                                ApplicationProtocol.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized Set<CommonDhValues> getCommonDhValues() {
        SetResult<CommonDhValues> setResult =
                getSetResult(TlsAnalyzedProperty.COMMON_DH_VALUES, CommonDhValues.class);
        return setResult == null ? null : setResult.getSet();
    }

    public synchronized Map<NamedGroup, NamedGroupWitness> getSupportedNamedGroupsWitnesses() {
        MapResult<NamedGroup, NamedGroupWitness> mapResult =
                getMapResult(
                        TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES,
                        NamedGroup.class,
                        NamedGroupWitness.class);
        return mapResult == null ? null : mapResult.getMap();
    }

    public synchronized Map<NamedGroup, NamedGroupWitness> getSupportedNamedGroupsWitnessesTls13() {
        MapResult<NamedGroup, NamedGroupWitness> mapResult =
                getMapResult(
                        TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES_TLS13,
                        NamedGroup.class,
                        NamedGroupWitness.class);
        return mapResult == null ? null : mapResult.getMap();
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
