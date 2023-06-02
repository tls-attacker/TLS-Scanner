/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.MapResult;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.constants.TestResults;
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
        @SuppressWarnings("unchecked")
        ListResult<InvalidCurveResponse> listResult =
                (ListResult<InvalidCurveResponse>)
                        getListResult(TlsAnalyzedProperty.INVALID_CURVE_TEST_RESULT);
        return listResult == null ? null : listResult.getList();
    }

    // TODO when is this NOTTESTEDYET set???
    public synchronized List<RaccoonAttackProbabilities> getRaccoonAttackProbabilities() {
        if (this.getResult(TlsAnalyzedProperty.RACCOON_ATTACK_PROBABILITIES)
                == TestResults.NOT_TESTED_YET) {
            return null;
        }
        @SuppressWarnings("unchecked")
        ListResult<RaccoonAttackProbabilities> listResult =
                (ListResult<RaccoonAttackProbabilities>)
                        this.getResult(TlsAnalyzedProperty.RACCOON_ATTACK_PROBABILITIES);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<OcspCertificateResult> getOcspResults() {
        @SuppressWarnings("unchecked")
        ListResult<OcspCertificateResult> listResult =
                (ListResult<OcspCertificateResult>)
                        this.getResult(TlsAnalyzedProperty.OCSP_RESULTS);
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
        @SuppressWarnings("unchecked")
        ListResult<CcaTestResult> listResult =
                (ListResult<CcaTestResult>) getListResult(TlsAnalyzedProperty.CCA_TEST_RESULTS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<HpkpPin> getNormalHpkpPins() {
        @SuppressWarnings("unchecked")
        ListResult<HpkpPin> listResult =
                (ListResult<HpkpPin>) getListResult(TlsAnalyzedProperty.NORMAL_HPKP_PINS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<HpkpPin> getReportOnlyHpkpPins() {
        @SuppressWarnings("unchecked")
        ListResult<HpkpPin> listResult =
                (ListResult<HpkpPin>) getListResult(TlsAnalyzedProperty.REPORT_ONLY_HPKP_PINS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<SimulatedClientResult> getSimulatedClientsResultList() {
        @SuppressWarnings("unchecked")
        ListResult<SimulatedClientResult> listResult =
                (ListResult<SimulatedClientResult>)
                        getListResult(TlsAnalyzedProperty.CLIENT_SIMULATION_RESULTS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<GuidelineReport> getGuidelineReports() {
        @SuppressWarnings("unchecked")
        ListResult<GuidelineReport> listResult =
                (ListResult<GuidelineReport>) getListResult(TlsAnalyzedProperty.GUIDELINE_REPORTS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<ApplicationProtocol> getSupportedApplicationProtocols() {
        @SuppressWarnings("unchecked")
        ListResult<ApplicationProtocol> listResult =
                (ListResult<ApplicationProtocol>)
                        getListResult(TlsAnalyzedProperty.SUPPORTED_APPLICATIONS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized Set<CommonDhValues> getCommonDhValues() {
        @SuppressWarnings("unchecked")
        SetResult<CommonDhValues> setResult =
                (SetResult<CommonDhValues>) getSetResult(TlsAnalyzedProperty.COMMON_DH_VALUES);
        return setResult == null ? null : setResult.getSet();
    }

    public synchronized Map<NamedGroup, NamedGroupWitness> getSupportedNamedGroupsWitnesses() {
        @SuppressWarnings("unchecked")
        MapResult<NamedGroup, NamedGroupWitness> mapResult =
                (MapResult<NamedGroup, NamedGroupWitness>)
                        getMapResult(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES);
        return mapResult == null ? null : mapResult.getMap();
    }

    public synchronized Map<NamedGroup, NamedGroupWitness> getSupportedNamedGroupsWitnessesTls13() {
        @SuppressWarnings("unchecked")
        MapResult<NamedGroup, NamedGroupWitness> mapResult =
                (MapResult<NamedGroup, NamedGroupWitness>)
                        getMapResult(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES_TLS13);
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
}
