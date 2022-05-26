/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestampList;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.constants.GcmPattern;
import de.rub.nds.tlsscanner.serverscanner.constants.ProtocolType;
import de.rub.nds.tlsscanner.serverscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.KnownPaddingOracleVulnerability;

public class ServerReport extends ScanReport {

    private final String host;
    private final Integer port;

    private Boolean serverIsAlive = null;
    private Boolean speaksProtocol = null;
    private Boolean isHandshaking = null;
    private ProtocolType protocolType = null;

    // Attacks
    private KnownPaddingOracleVulnerability knownVulnerability = null;

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
    private Integer hpkpMaxAge = null;

    // DTLS
    private Integer totalReceivedRetransmissions = 0;
    private Integer cookieLength = null;

    // PublicKey Params
    private Integer weakestDhStrength = null;

    // Handshake Simulation
    private Integer handshakeSuccessfulCounter = null;
    private Integer handshakeFailedCounter = null;
    private Integer connectionRfc7918SecureCounter = null;
    private Integer connectionInsecureCounter = null;

    // CCA
    private Boolean ccaSupported = null;
    private Boolean ccaRequired = null;

    private Long closedAfterFinishedDelta;
    private Long closedAfterAppDataDelta;

    private int performedTcpConnections = 0;

    // Rating
    private int score;
    private ScoreReport scoreReport;

    // Scan Timestamps
    private long scanStartTime;
    private long scanEndTime;

    public ServerReport() {
        host = null;
        port = null;
    }

    public ServerReport(String host, int port) {
        super();
        this.host = host;
        this.port = port;
    }

    public synchronized ProtocolType getProtocolType() {
        return protocolType;
    }

    public synchronized void setProtocolType(ProtocolType protocolType) {
        this.protocolType = protocolType;
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

    public synchronized Integer getTotalReceivedRetransmissions() {
        return totalReceivedRetransmissions;
    }

    public synchronized void setTotalReceivedRetransmissions(Integer totalReceivedRetransmissions) {
        this.totalReceivedRetransmissions = totalReceivedRetransmissions;
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

    public synchronized void setConnectionRfc7918SecureCounter(Integer connectionRfc7918SecureCounter) {
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
        return new ServerReportPrinter(this, detail, DefaultPrintingScheme.getDefaultPrintingScheme(printColorful),
            printColorful).getFullReport();
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

    public synchronized KnownPaddingOracleVulnerability getKnownVulnerability() {
        return knownVulnerability;
    }

    public synchronized void setKnownVulnerability(KnownPaddingOracleVulnerability knownVulnerability) {
        this.knownVulnerability = knownVulnerability;
    }

    public synchronized Boolean getCcaSupported() {
        return this.getResult(TlsAnalyzedProperty.SUPPORTS_CCA) == TestResults.TRUE;
    }

    public synchronized Boolean getCcaRequired() {
        return this.getResult(TlsAnalyzedProperty.REQUIRES_CCA) == TestResults.TRUE;
    }

    public synchronized SignedCertificateTimestampList getPrecertificateSctList() {
        return precertificateSctList;
    }

    public synchronized void setPrecertificateSctList(SignedCertificateTimestampList precertificateSctList) {
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

    public synchronized long getScanStartTime() {
        return scanStartTime;
    }

    public synchronized void setScanStartTime(long scanStartTime) {
        this.scanStartTime = scanStartTime;
    }

    public synchronized long getScanEndTime() {
        return scanEndTime;
    }

    public synchronized void setScanEndTime(long scanEndTime) {
        this.scanEndTime = scanEndTime;
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

    public synchronized void setHelloRetryRequestSelectedNamedGroup(NamedGroup helloRetryRequestSelectedNamedGroup) {
        this.helloRetryRequestSelectedNamedGroup = helloRetryRequestSelectedNamedGroup;
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
}
