/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateType;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowType;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestamp;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.AlpnProtocol;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDsaPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.serverscanner.constants.AnsiColor;
import de.rub.nds.tlsscanner.serverscanner.constants.CipherSuiteGrade;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateIssue;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.ConnectionInsecure;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.HandshakeFailureReasons;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.InvalidCurveResponse;
import de.rub.nds.tlsscanner.serverscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.serverscanner.probe.namedcurve.NamedCurveWitness;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.PaddingOracleStrength;
import de.rub.nds.tlsscanner.serverscanner.rating.PropertyResultRatingInfluencer;
import de.rub.nds.tlsscanner.serverscanner.rating.PropertyResultRecommendation;
import de.rub.nds.tlsscanner.serverscanner.rating.Recommendation;
import de.rub.nds.tlsscanner.serverscanner.rating.ScoreReport;
import de.rub.nds.tlsscanner.serverscanner.rating.SiteReportRater;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.after.prime.CommonDhValues;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.report.result.cca.CcaTestResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.serverscanner.report.result.ocsp.OcspCertificateResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.raccoonattack.RaccoonAttackProbabilities;
import de.rub.nds.tlsscanner.serverscanner.report.result.raccoonattack.RaccoonAttackPskProbabilities;
import de.rub.nds.tlsscanner.serverscanner.report.result.statistics.CookieEvaluationResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.statistics.RandomEvaluationResult;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.ResponseCounter;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.VectorContainer;
import static de.rub.nds.tlsscanner.serverscanner.report.result.statistics.RandomEvaluationResult.DUPLICATES;
import static de.rub.nds.tlsscanner.serverscanner.report.result.statistics.RandomEvaluationResult.NOT_ANALYZED;
import static de.rub.nds.tlsscanner.serverscanner.report.result.statistics.RandomEvaluationResult.NOT_RANDOM;
import static de.rub.nds.tlsscanner.serverscanner.report.result.statistics.RandomEvaluationResult.NO_DUPLICATES;
import java.security.PublicKey;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.Duration;
import org.joda.time.Period;
import org.joda.time.format.PeriodFormat;

public class SiteReportPrinter {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SiteReport report;
    private final ScannerDetail detail;
    private int depth;

    private final String hsClientFormat = "%-28s";
    private final String hsVersionFormat = "%-14s";
    private final String hsCipherSuiteFormat = "%-52s";
    private final String hsForwardSecrecyFormat = "%-19s";
    private final String hsKeyLengthFormat = "%-17s";
    private final PrintingScheme scheme;
    private final boolean printColorful;

    public SiteReportPrinter(SiteReport report, ScannerDetail detail, boolean printColorful) {
        this.report = report;
        this.detail = detail;
        depth = 0;
        this.printColorful = printColorful;
        scheme = PrintingScheme.getDefaultPrintingScheme(printColorful);
    }

    public SiteReportPrinter(SiteReport report, ScannerDetail detail, PrintingScheme scheme, boolean printColorful) {
        this.report = report;
        this.detail = detail;
        depth = 0;
        this.scheme = scheme;
        this.printColorful = printColorful;
    }

    public String getFullReport() {
        StringBuilder builder = new StringBuilder();
        builder.append("Report for ");
        builder.append(report.getHost());
        builder.append("\n");
        if (report.getServerIsAlive() == Boolean.FALSE) {
            builder.append("Cannot reach the Server. Is it online?");
            return builder.toString();
        }
        if (report.getSupportsSslTls() == Boolean.FALSE) {
            builder.append("Server does not seem to support SSL / TLS on the scanned port");
            return builder.toString();
        }
        if (report.getSupportsDtls() == Boolean.FALSE) {
            builder.append("Server does not seem to support DTLS on the scanned port");
            return builder.toString();
        }
        //
        appendProtocolVersions(builder);
        appendCipherSuites(builder);
        appendExtensions(builder);
        appendCompressions(builder);
        appendEcPointFormats(builder);
        appendRecordFragmentation(builder);
        appendAlpn(builder);
        appendIntolerances(builder);
        appendHelloRetry(builder);
        appendAttackVulnerabilities(builder);
        appendAlpacaAttack(builder);
        appendBleichenbacherResults(builder);
        appendPaddingOracleResults(builder);
        sessionTicketZeroKeyDetails(builder);
        appendDirectRaccoonResults(builder);
        appendInvalidCurveResults(builder);
        appendRaccoonAttackDetails(builder);
        // appendGcm(builder);
        // appendRfc(builder);
        appendCertificates(builder);
        appendOcsp(builder);
        appendCertificateTransparency(builder);
        appendSession(builder);
        appendRenegotiation(builder);
        appendHandshakeSimulation(builder);
        appendHttps(builder);
        appendRandom(builder);
        appendPublicKeyIssues(builder);
        appendClientAuthentication(builder);
        if (report.getSupportsDtls() == Boolean.TRUE) {
            appendDtlsSpecificResults(builder);
        }
        appendScoringResults(builder);
        appendRecommendations(builder);
        appendPerformanceData(builder);

        return builder.toString();
    }

    private void appendDtlsSpecificResults(StringBuilder builder) {
        prettyAppendHeading(builder, "DTLS [EXPERIMENTAL]");
        prettyAppend(builder, "Accept unencrypted App Data with Epoch 0", AnalyzedProperty.ACCEPT_UNENCRYPTED_APP_DATA);
        prettyAppend(builder, "Early Finished", AnalyzedProperty.HAS_EARLY_FINISHED_BUG);
        prettyAppend(builder, "Overwrites Content", AnalyzedProperty.OVERWRITES_CONTENT);
        prettyAppendHeading(builder, "DTLS Hello Verify Request");
        prettyAppendCookie(builder, "Cookie", report.getCookieEvaluationResult());
        prettyAppend(builder, "Checks complete", AnalyzedProperty.HAS_COOKIE_CHECKS);
        prettyAppend(builder, "Checks with client parameters",
            AnalyzedProperty.USES_CLIENT_PARAMERTS_FOR_COOKIE_CHECKS);
        prettyAppendHeading(builder, "DTLS Message Sequences");
        prettyAppend(builder, "Starts handshake with invalid msg seq",
            AnalyzedProperty.STARTS_WITH_INVALID_MESSAGE_SEQUENCE);
        prettyAppend(builder, "Misses msg seq checks", AnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS);
        prettyAppendHeading(builder, "DTLS Sequence Numbers");
        prettyAppend(builder, "Has retransmission bug", AnalyzedProperty.HAS_RETRANSMISSION_BUG);
    }

    private void appendDirectRaccoonResults(StringBuilder builder) {
        // TODO this recopying is weired
        List<InformationLeakTest> informationLeakTestList = new LinkedList<>();
        if (report.getDirectRaccoonResultList() == null) {
            return;
        }
        informationLeakTestList.addAll(report.getDirectRaccoonResultList());
        appendInformationLeakTestList(builder, informationLeakTestList, "Direct Raccoon Results");
    }

    public StringBuilder appendHandshakeSimulation(StringBuilder builder) {
        if (report.getSimulatedClientList() != null) {
            appendHsNormal(builder);
            if (detail == ScannerDetail.DETAILED) {
                appendHandshakeSimulationTable(builder);
            } else if (detail == ScannerDetail.ALL) {
                appendHandshakeSimulationTable(builder);
                appendHandshakeSimulationDetails(builder);
            }
        }
        return builder;
    }

    public StringBuilder appendHsNormal(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation - Overview");
        prettyAppend(builder, "Tested Clients", Integer.toString(report.getSimulatedClientList().size()));
        builder.append("\n");
        String identifier;
        identifier = "Handshakes - Successful";
        if (report.getHandshakeSuccessfulCounter() == 0) {
            prettyAppend(builder, identifier, Integer.toString(report.getHandshakeSuccessfulCounter()), AnsiColor.RED);
        } else {
            prettyAppend(builder, identifier, Integer.toString(report.getHandshakeSuccessfulCounter()),
                AnsiColor.GREEN);
        }
        identifier = "Handshakes - Failed";
        if (report.getHandshakeFailedCounter() == 0) {
            prettyAppend(builder, identifier, Integer.toString(report.getHandshakeFailedCounter()), AnsiColor.GREEN);
        } else {
            prettyAppend(builder, identifier, Integer.toString(report.getHandshakeFailedCounter()), AnsiColor.RED);
        }
        builder.append("\n");
        return builder;
    }

    public StringBuilder appendHandshakeSimulationTable(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation");
        int counter = 0;
        appendHandshakeSimulationTableRowHeading(builder, "Client", "Version", "CipherSuite", "Forward Secrecy",
            "Server Public Key");
        builder.append("\n");
        for (SimulatedClientResult simulatedClient : report.getSimulatedClientList()) {
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || simulatedClient.getTlsClientConfig().isDefaultVersion()) {
                if (simulatedClient.getHandshakeSuccessful()) {
                    appendHandshakeTableRowSuccessful(builder, simulatedClient);
                    counter++;
                } else {
                    appendHandshakeTableRowFailed(builder, simulatedClient);
                    counter++;
                }
            }
        }

        if (counter == 0) {
            prettyAppend(builder, "-");
        }
        return builder;
    }

    public StringBuilder appendHandshakeSimulationTableRowHeading(StringBuilder builder, String tlsClient,
        String tlsVersion, String cipherSuite, String forwardSecrecy, String keyLength) {
        builder.append(String.format(hsClientFormat, tlsClient));
        builder.append(String.format("| " + hsVersionFormat, tlsVersion));
        builder.append(String.format("| " + hsCipherSuiteFormat, cipherSuite));
        builder.append(String.format("| " + hsForwardSecrecyFormat, forwardSecrecy));
        builder.append(String.format("| " + hsKeyLengthFormat, keyLength));
        builder.append("\n");
        return builder;
    }

    public StringBuilder appendHandshakeTableRowSuccessful(StringBuilder builder,
        SimulatedClientResult simulatedClient) {
        String clientName =
            simulatedClient.getTlsClientConfig().getType() + ":" + simulatedClient.getTlsClientConfig().getVersion();
        builder.append(getClientColor(clientName, simulatedClient.getConnectionInsecure(),
            simulatedClient.getConnectionRfc7918Secure()));
        builder.append("| ")
            .append(getProtocolVersionColor(simulatedClient.getSelectedProtocolVersion(), hsVersionFormat));
        builder.append("| ").append(getCipherSuiteColor(simulatedClient.getSelectedCipherSuite(), hsCipherSuiteFormat));
        builder.append("| ").append(getForwardSecrecyColor(simulatedClient.getForwardSecrecy()));
        builder.append("| ").append(getServerPublicKeyParameterColor(simulatedClient));
        builder.append("\n");
        return builder;
    }

    public StringBuilder appendHandshakeTableRowFailed(StringBuilder builder, SimulatedClientResult simulatedClient) {
        // String clientName = simulatedClient.getTlsClientConfig().getType() +
        // ":"
        // + simulatedClient.getTlsClientConfig().getVersion();
        // builder.append(String.format("%s", getRedString(clientName,
        // hsClientFormat)));
        // if (!simulatedClient.getFailReasons().isEmpty()) {
        // for (HandshakeFailureReasons reason :
        // simulatedClient.getFailReasons()) {
        // builder.append(String.format("| %s", getRedString(reason.getReason(),
        // hsVersionFormat)));
        // }
        // } else {
        // ReceivingAction action =
        // simulatedClient.getState().getWorkflowTrace().getLastReceivingAction();
        // if (action.getReceivedMessages().isEmpty()) {
        // builder.append(String.format("| %s",
        // getRedString("Failed - No answer from server", "%s")));
        // } else {
        // StringBuilder messages = new StringBuilder();
        // for (ProtocolMessage message : action.getReceivedMessages()) {
        // messages.append(message.toCompactString()).append(", ");
        // }
        // builder.append(String.format("| %s", getRedString("Failed - " +
        // messages, "%s")));
        // }
        // }
        builder.append("\n");
        return builder;
    }

    private String getClientColor(String tlsClient, Boolean insecure, Boolean rfc7918Secure) {
        if (tlsClient != null) {
            if (insecure != null && insecure) {
                return getRedString(tlsClient, hsClientFormat);
            } else if (rfc7918Secure != null && rfc7918Secure) {
                return getGreenString(tlsClient, hsClientFormat);
            }
        } else {
            return "Unknown";
        }
        return getBlackString(tlsClient, hsClientFormat);
    }

    private String getProtocolVersionColor(ProtocolVersion version, String format) {
        if (version != null) {
            if (version.name().contains("13") || version.name().contains("12")) {
                return getGreenString(version.name(), format);
            } else if (version.name().contains("11") || version.name().contains("10")) {
                return getYellowString(version.name(), format);
            } else if (version.name().contains("SSL")) {
                return getRedString(version.name(), format);
            } else {
                return getBlackString(version.name(), format);
            }
        } else {
            return "Unknown";
        }
    }

    private String getCipherSuiteColor(CipherSuite suite, String format) {
        if (suite != null) {
            CipherSuiteGrade grade = CipherSuiteRater.getGrade(suite);
            switch (grade) {
                case GOOD:
                    return getGreenString(suite.name(), format);
                case LOW:
                    return getRedString(suite.name(), format);
                case MEDIUM:
                    return getYellowString(suite.name(), format);
                case NONE:
                    return getBlackString(suite.name(), format);
                default:
                    return getBlackString(suite.name(), format);
            }
        } else {
            return "Unknown";
        }
    }

    private String getForwardSecrecyColor(Boolean forwardSecrecy) {
        String fs;
        if (forwardSecrecy != null) {
            if (forwardSecrecy) {
                fs = getGreenString("Forward Secrecy", hsForwardSecrecyFormat);
            } else {
                fs = getRedString("No Forward Secrecy", hsForwardSecrecyFormat);
            }
        } else {
            fs = "Unknown";
        }
        return fs;
    }

    private String getServerPublicKeyParameterColor(SimulatedClientResult simulatedClient) {
        String pubKeyParam = getServerPublicKeyParameterToPrint(simulatedClient);
        if (simulatedClient.getServerPublicKeyParameter() != null) {
            if (simulatedClient.getInsecureReasons() != null) {
                for (String reason : simulatedClient.getInsecureReasons()) {
                    if (reason.contains(ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason())) {
                        return getRedString(pubKeyParam, "%s");
                    }
                }
            }
            return getGreenString(pubKeyParam, "%s");
        }
        return getBlackString(pubKeyParam, "%s");
    }

    private String getServerPublicKeyParameterToPrint(SimulatedClientResult simulatedClient) {
        CipherSuite suite = simulatedClient.getSelectedCipherSuite();
        Integer param = simulatedClient.getServerPublicKeyParameter();
        if (suite != null && param != null) {
            if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeRsa()) {
                return param + " bit - RSA";
            } else if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeDh()) {
                return param + " bit - DH";
            } else if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeEcdh()) {
                return param + " bit - ECDH - " + simulatedClient.getSelectedNamedGroup();
            }
        }
        return null;
    }

    public StringBuilder appendHandshakeSimulationDetails(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation - Details");
        for (SimulatedClientResult simulatedClient : report.getSimulatedClientList()) {
            prettyAppendHeading(builder, simulatedClient.getTlsClientConfig().getType() + ":"
                + simulatedClient.getTlsClientConfig().getVersion());
            prettyAppend(builder, "Handshake Successful", "" + simulatedClient.getHandshakeSuccessful(),
                simulatedClient.getHandshakeSuccessful() ? AnsiColor.GREEN : AnsiColor.RED);
            if (!simulatedClient.getHandshakeSuccessful()) {
                for (HandshakeFailureReasons failureReason : simulatedClient.getFailReasons()) {
                    prettyAppend(builder, "", getRedString(failureReason.getReason(), "%s"));
                }
            }
            builder.append("\n");
            if (simulatedClient.getConnectionInsecure() != null && simulatedClient.getConnectionInsecure()) {
                prettyAppend(builder, "Connection Insecure", simulatedClient.getConnectionInsecure(),
                    simulatedClient.getConnectionInsecure() ? AnsiColor.RED : AnsiColor.GREEN);
                for (String reason : simulatedClient.getInsecureReasons()) {
                    prettyAppend(builder, "", reason);
                }
            }
            prettyAppend(builder, "Connection Secure (RFC 7918)", simulatedClient.getConnectionRfc7918Secure(),
                simulatedClient.getConnectionRfc7918Secure() ? AnsiColor.GREEN : AnsiColor.DEFAULT_COLOR);

            builder.append("\n");
            prettyAppend(builder, "Protocol Version Selected",
                getProtocolVersionColor(simulatedClient.getSelectedProtocolVersion(), "%s"));
            prettyAppend(builder, "Protocol Versions Client", simulatedClient.getSupportedVersionList().toString());
            prettyAppend(builder, "Protocol Versions Server", report.getVersions().toString());
            prettyAppend(builder, "Protocol Version is highest",
                simulatedClient.getHighestPossibleProtocolVersionSelected(),
                simulatedClient.getHighestPossibleProtocolVersionSelected() ? AnsiColor.GREEN : AnsiColor.RED);
            builder.append("\n");
            prettyAppend(builder, "Selected CipherSuite",
                getCipherSuiteColor(simulatedClient.getSelectedCipherSuite(), "%s"));
            prettyAppend(builder, "Forward Secrecy", simulatedClient.getForwardSecrecy(),
                simulatedClient.getForwardSecrecy() ? AnsiColor.GREEN : AnsiColor.RED);
            builder.append("\n");
            prettyAppend(builder, "Server Public Key", getServerPublicKeyParameterColor(simulatedClient));
            builder.append("\n");
            if (simulatedClient.getSelectedCompressionMethod() != null) {
                prettyAppend(builder, "Selected Compression Method",
                    simulatedClient.getSelectedCompressionMethod().toString());
            } else {
                String tmp = null;
                prettyAppend(builder, "Selected Compression Method", tmp);
            }
            prettyAppend(builder, "Negotiated Extensions", simulatedClient.getNegotiatedExtensions());
            // prettyAppend(builder, "Alpn Protocols", simulatedClient.getAlpnAnnouncedProtocols());
        }
        return builder;
    }

    public StringBuilder appendRfc(StringBuilder builder) {
        prettyAppendHeading(builder, "RFC (Experimental)");
        prettyAppendCheckPattern(builder, "Checks MAC (AppData)", report.getMacCheckPatternAppData());
        prettyAppendCheckPattern(builder, "Checks MAC (Finished)", report.getMacCheckPatternFinished());
        prettyAppendCheckPattern(builder, "Checks VerifyData", report.getVerifyCheckPattern());
        return builder;
    }

    public StringBuilder appendRenegotiation(StringBuilder builder) {
        prettyAppendHeading(builder, "Renegotioation");
        prettyAppend(builder, "Secure (Extension)",
            AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION);
        prettyAppend(builder, "Secure (CipherSuite)",
            AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE);
        prettyAppend(builder, "Insecure", AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION);
        return builder;
    }

    public StringBuilder appendCertificates(StringBuilder builder) {
        int certCtr = 1;
        if (report.getCertificateChainList() != null && report.getCertificateChainList().isEmpty() == false) {
            for (CertificateChain chain : report.getCertificateChainList()) {
                prettyAppendHeading(builder, "Certificate Chain (Certificate " + certCtr + " of "
                    + report.getCertificateChainList().size() + ")");
                appendCertificate(builder, chain);
                certCtr++;
            }
        }

        return builder;
    }

    private StringBuilder appendCertificate(StringBuilder builder, CertificateChain chain) {
        prettyAppend(builder, "Chain ordered", chain.getChainIsOrdered(),
            chain.getChainIsOrdered() ? AnsiColor.GREEN : AnsiColor.YELLOW);
        prettyAppend(builder, "Contains Trust Anchor", chain.getContainsTrustAnchor(),
            chain.getContainsTrustAnchor() ? AnsiColor.RED : AnsiColor.GREEN);
        prettyAppend(builder, "Generally Trusted", chain.getGenerallyTrusted(),
            chain.getGenerallyTrusted() ? AnsiColor.GREEN : AnsiColor.RED);
        if (chain.getCertificateIssues().size() > 0) {
            prettyAppendSubheading(builder, "Certificate Issues");
            for (CertificateIssue issue : chain.getCertificateIssues()) {
                prettyAppend(builder, issue.getHumanReadable(), AnsiColor.RED);
            }
        }
        if (!chain.getCertificateReportList().isEmpty()) {
            for (int i = 0; i < chain.getCertificateReportList().size(); i++) {
                CertificateReport certReport = chain.getCertificateReportList().get(i);
                prettyAppendSubheading(builder, "Certificate #" + (i + 1));

                if (certReport.getSubject() != null) {
                    prettyAppend(builder, "Subject", certReport.getSubject());
                }

                if (certReport.getIssuer() != null) {
                    prettyAppend(builder, "Issuer", certReport.getIssuer());
                }
                if (certReport.getValidFrom() != null) {
                    if (certReport.getValidFrom().before(new Date())) {
                        prettyAppend(builder, "Valid From", certReport.getValidFrom().toString(), AnsiColor.GREEN);
                    } else {
                        prettyAppend(builder, "Valid From", certReport.getValidFrom().toString() + " - NOT YET VALID",
                            AnsiColor.RED);
                    }
                }
                if (certReport.getValidTo() != null) {
                    if (certReport.getValidTo().after(new Date())) {
                        prettyAppend(builder, "Valid Till", certReport.getValidTo().toString(), AnsiColor.GREEN);
                    } else {
                        prettyAppend(builder, "Valid Till", certReport.getValidTo().toString() + " - EXPIRED",
                            AnsiColor.RED);
                    }

                }
                if (certReport.getValidFrom() != null && certReport.getValidTo() != null
                    && certReport.getValidTo().after(new Date())) {
                    long time = certReport.getValidTo().getTime() - System.currentTimeMillis();
                    long days = TimeUnit.MILLISECONDS.toDays(time);
                    if (days < 1) {
                        prettyAppend(builder, "Expires in", "<1 day! This certificate expires very soon",
                            AnsiColor.RED);
                    } else if (days < 3) {
                        prettyAppend(builder, "Expires in", days + " days! This certificate expires soon",
                            AnsiColor.RED);
                    } else if (days < 14) {
                        prettyAppend(builder, "Expires in", days + " days. This certificate expires soon",
                            AnsiColor.YELLOW);
                    } else if (days < 31) {
                        prettyAppend(builder, "Expires in", days + " days.", AnsiColor.DEFAULT_COLOR);
                    } else if (days < 730) {
                        prettyAppend(builder, "Expires in", days + " days.", AnsiColor.GREEN);
                    } else if (Objects.equals(certReport.getLeafCertificate(), Boolean.TRUE)) {
                        prettyAppend(builder, "Expires in",
                            days + " days. This is usually too long for a leaf certificate", AnsiColor.RED);
                    } else {
                        prettyAppend(builder, "Expires in", days / 365 + " years", AnsiColor.GREEN);
                    }
                }
                if (certReport.getPublicKey() != null) {
                    prettyAppendPublicKey(builder, certReport.getPublicKey());
                }
                if (certReport.getWeakDebianKey() != null) {
                    prettyAppend(builder, "Weak Debian Key", certReport.getWeakDebianKey(),
                        certReport.getWeakDebianKey() ? AnsiColor.RED : AnsiColor.GREEN);
                }
                if (certReport.getSignatureAndHashAlgorithm() != null) {
                    prettyAppend(builder, "Signature Algorithm",
                        certReport.getSignatureAndHashAlgorithm().getSignatureAlgorithm().name());
                }
                if (certReport.getSignatureAndHashAlgorithm() != null) {
                    if (certReport.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.SHA1
                        || certReport.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.MD5) {
                        if (!certReport.isTrustAnchor() && !certReport.getSelfSigned()) {
                            prettyAppend(builder, "Hash Algorithm",
                                certReport.getSignatureAndHashAlgorithm().getHashAlgorithm().name(), AnsiColor.RED);
                        } else {
                            prettyAppend(builder, "Hash Algorithm",
                                certReport.getSignatureAndHashAlgorithm().getHashAlgorithm().name()
                                    + " - Not critical");
                        }
                    } else {
                        prettyAppend(builder, "Hash Algorithm",
                            certReport.getSignatureAndHashAlgorithm().getHashAlgorithm().name(), AnsiColor.GREEN);
                    }
                }
                if (certReport.getExtendedValidation() != null) {
                    prettyAppend(builder, "Extended Validation", certReport.getExtendedValidation(),
                        certReport.getExtendedValidation() ? AnsiColor.GREEN : AnsiColor.DEFAULT_COLOR);
                }
                if (certReport.getCertificateTransparency() != null) {
                    prettyAppend(builder, "Certificate Transparency", certReport.getCertificateTransparency(),
                        certReport.getCertificateTransparency() ? AnsiColor.GREEN : AnsiColor.YELLOW);
                }

                if (certReport.getCrlSupported() != null) {
                    prettyAppend(builder, "CRL Supported", certReport.getCrlSupported(),
                        certReport.getCrlSupported() ? AnsiColor.GREEN : AnsiColor.DEFAULT_COLOR);
                }
                if (certReport.getOcspSupported() != null) {
                    prettyAppend(builder, "OCSP Supported", certReport.getOcspSupported(),
                        certReport.getOcspSupported() ? AnsiColor.GREEN : AnsiColor.YELLOW);
                }
                if (certReport.getOcspMustStaple() != null) {
                    prettyAppend(builder, "OCSP must Staple", certReport.getOcspMustStaple());
                }
                if (certReport.getRevoked() != null) {
                    prettyAppend(builder, "RevocationStatus", certReport.getRevoked(),
                        certReport.getRevoked() ? AnsiColor.RED : AnsiColor.GREEN);
                }
                if (certReport.getDnsCAA() != null) {
                    prettyAppend(builder, "DNS CCA", certReport.getDnsCAA(),
                        certReport.getDnsCAA() ? AnsiColor.GREEN : AnsiColor.DEFAULT_COLOR);
                }
                if (certReport.getRocaVulnerable() != null) {
                    prettyAppend(builder, "ROCA (simple)", certReport.getRocaVulnerable(),
                        certReport.getRocaVulnerable() ? AnsiColor.RED : AnsiColor.GREEN);
                } else {
                    builder.append("ROCA (simple): not tested");
                }
                prettyAppend(builder, "Fingerprint (SHA256)", certReport.getSHA256Fingerprint());

            }
        }
        return builder;
    }

    private String prettyAppendPublicKey(StringBuilder builder, PublicKey publicKey) {
        if (publicKey instanceof CustomDhPublicKey) {
            CustomDhPublicKey dhPublicKey = (CustomDhPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "Static Diffie Hellman");

            prettyAppend(builder, "Modulus", dhPublicKey.getModulus().toString(16));
            prettyAppend(builder, "Generator", dhPublicKey.getModulus().toString(16));
            prettyAppend(builder, "Y", dhPublicKey.getY().toString(16));
        } else if (publicKey instanceof CustomDsaPublicKey) {
            CustomDsaPublicKey dsaPublicKey = (CustomDsaPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "DSA");
            prettyAppend(builder, "Modulus", dsaPublicKey.getDsaP().toString(16));
            prettyAppend(builder, "Generator", dsaPublicKey.getDsaG().toString(16));
            prettyAppend(builder, "Q", dsaPublicKey.getDsaQ().toString(16));
            prettyAppend(builder, "X", dsaPublicKey.getY().toString(16));
        } else if (publicKey instanceof CustomRsaPublicKey) {
            CustomRsaPublicKey rsaPublicKey = (CustomRsaPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "RSA");
            prettyAppend(builder, "Modulus", rsaPublicKey.getModulus().toString(16));
            prettyAppend(builder, "Public exponent", rsaPublicKey.getPublicExponent().toString(16));
        } else if (publicKey instanceof CustomEcPublicKey) {
            CustomEcPublicKey ecPublicKey = (CustomEcPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "EC");
            if (ecPublicKey.getGroup() == null) {
                prettyAppend(builder, "Group (GOST)", ecPublicKey.getGostCurve().name());
            } else {
                prettyAppend(builder, "Group", ecPublicKey.getGroup().name());
            }
            prettyAppend(builder, "Public Point", ecPublicKey.getPoint().toString());
        } else {
            builder.append(publicKey.toString()).append("\n");
        }
        return builder.toString();
    }

    private StringBuilder appendOcsp(StringBuilder builder) {
        prettyAppendHeading(builder, "OCSP");
        appendOcspOverview(builder);
        if (report.getOcspResults() != null) {
            int certCtr = 1;
            for (OcspCertificateResult result : report.getOcspResults()) {
                prettyAppendSubheading(builder,
                    "Detailed OCSP results for certificate " + certCtr + " of " + report.getOcspResults().size());
                appendOcspForCertificate(builder, result);
                certCtr++;
            }
        }

        return builder;
    }

    private StringBuilder appendOcspOverview(StringBuilder builder) {
        prettyAppend(builder, "Supports OCSP ", AnalyzedProperty.SUPPORTS_OCSP);
        // In case extension probe & OCSP probe differ, report stapling as
        // unreliable.
        if (report.getResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST) == TestResult.TRUE
            && report.getResult(AnalyzedProperty.SUPPORTS_OCSP_STAPLING) == TestResult.FALSE) {
            prettyAppend(builder, "OCSP Stapling is unreliable on this server.", AnsiColor.YELLOW);
            prettyAppend(builder, "Extension scan reported OCSP Stapling support, but OCSP scan does not.",
                AnsiColor.YELLOW);
            prettyAppend(builder, "The results are likely incomplete. Maybe rescan for more information? \n",
                AnsiColor.RED);
            report.putResult(AnalyzedProperty.STAPLING_UNRELIABLE, TestResult.TRUE);
        } else if (report.getResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST) == TestResult.FALSE
            && report.getResult(AnalyzedProperty.SUPPORTS_OCSP_STAPLING) == TestResult.TRUE) {
            prettyAppend(builder, "OCSP Stapling is unreliable on this server.", AnsiColor.YELLOW);
            prettyAppend(builder, "Extension scan reported no OCSP support, but OCSP scan does. \n", AnsiColor.YELLOW);
            report.putResult(AnalyzedProperty.STAPLING_UNRELIABLE, TestResult.TRUE);
        }

        // Print stapling support & 'must-staple'
        if (report.getResult(AnalyzedProperty.STAPLING_UNRELIABLE) == TestResult.TRUE) {
            prettyAppend(builder, "OCSP Stapling", "true, but unreliable", AnsiColor.YELLOW);
            if (report.getResult(AnalyzedProperty.MUST_STAPLE) == TestResult.TRUE) {
                prettyAppend(builder, "Must Staple", "true", AnsiColor.RED);
            } else {
                prettyAppend(builder, "Must Staple", AnalyzedProperty.MUST_STAPLE);
            }
        } else {
            if (report.getResult(AnalyzedProperty.MUST_STAPLE) == TestResult.TRUE) {
                if (report.getResult(AnalyzedProperty.SUPPORTS_OCSP_STAPLING) == TestResult.TRUE) {
                    prettyAppend(builder, "OCSP Stapling", "true", AnsiColor.GREEN);
                } else {
                    prettyAppend(builder, "OCSP Stapling", "false", AnsiColor.RED);
                }
                prettyAppend(builder, "Must Staple", "true", AnsiColor.GREEN);
            } else {
                prettyAppend(builder, "OCSP Stapling", AnalyzedProperty.SUPPORTS_OCSP_STAPLING);
                prettyAppend(builder, "Must Staple", AnalyzedProperty.MUST_STAPLE);
            }
        }

        if (report.getResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13) != TestResult.COULD_NOT_TEST) {
            prettyAppend(builder, "OCSP Stapling (TLS 1.3)",
                AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13);
            prettyAppend(builder, "Multi Stapling (TLS 1.3)", AnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES);
        }

        if (Boolean.TRUE.equals(report.getResult(AnalyzedProperty.SUPPORTS_NONCE) == TestResult.TRUE)) {
            prettyAppend(builder, "Nonce Mismatch / Cached Nonce", AnalyzedProperty.NONCE_MISMATCH);
        }

        // Is stapling supported, but a CertificateStatus message is missing?
        if (report.getResult(AnalyzedProperty.SUPPORTS_OCSP_STAPLING) == TestResult.TRUE) {
            prettyAppend(builder, "Includes Stapled Response", AnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE);
            prettyAppend(builder, "Stapled Response Expired", AnalyzedProperty.STAPLED_RESPONSE_EXPIRED);
        }

        // Are nonces used? If so, do they match?
        prettyAppend(builder, "Supports Nonce", AnalyzedProperty.SUPPORTS_NONCE);
        if (Boolean.TRUE.equals(report.getResult(AnalyzedProperty.SUPPORTS_NONCE) == TestResult.TRUE)) {
            prettyAppend(builder, "Nonce Mismatch / Cached Nonce", AnalyzedProperty.NONCE_MISMATCH);
        }

        return builder;
    }

    private StringBuilder appendOcspForCertificate(StringBuilder builder, OcspCertificateResult result) {
        if (result.isSupportsStapling()) {
            if (result.getStapledResponse() != null) {
                prettyAppend(builder, "Includes Stapled Response", true);
                if (result.getFirstResponse().getResponseStatus() == 0) {
                    long differenceHoursStapled = result.getDifferenceHoursStapled();
                    if (differenceHoursStapled < 24) {
                        prettyAppend(builder, "Stapled Response Cached", differenceHoursStapled + " hours",
                            AnsiColor.GREEN);
                    } else {
                        prettyAppend(builder, "Stapled Response Cached", differenceHoursStapled / 24 + " days",
                            AnsiColor.YELLOW);
                    }
                    prettyAppend(builder, "Stapled Response Expired", result.isStapledResponseExpired());
                }
                prettyAppend(builder, "Supports Stapled Nonce", result.isSupportsStapledNonce());
            } else {
                prettyAppend(builder, "Includes Stapled Response", false);
            }
        }

        prettyAppend(builder, "Supports Nonce", result.isSupportsNonce());
        prettyAppend(builder, "Nonce Mismatch / Cached Nonce", result.isNonceMismatch());

        if (result.getStapledResponse() != null) {
            prettyAppendSubheading(builder, "Stapled OCSP Response");
            if (result.getStapledResponse().getResponseStatus() > 0) {
                prettyAppend(builder, "Server stapled an erroneous OCSP response. \n", AnsiColor.RED);
            }
            prettyAppend(builder, result.getStapledResponse().toString(false));
        }

        if (result.getFirstResponse() != null) {
            prettyAppendSubheading(builder, "Requested OCSP Response (HTTP POST)");
            if (result.getFirstResponse().getResponseStatus() > 0) {
                prettyAppend(builder, "OCSP Request was not accepted by the OCSP Responder.", AnsiColor.RED);

                // Check if certificate chain was unordered. This will make the
                // request fail very likely.
                CertificateChain chain = result.getCertificate();
                if (Boolean.FALSE.equals(chain.getChainIsOrdered())) {
                    prettyAppend(builder,
                        "This likely happened due the certificate chain being unordered. This is not supported yet by this scan.",
                        AnsiColor.RED);
                }
                prettyAppend(builder, result.getFirstResponse().toString(false));
            }
        } else if (result.getFirstResponse() == null && result.getHttpGetResponse() != null) {
            prettyAppend(builder, "Retrieved an OCSP response via HTTP GET, but not via HTTP POST.", AnsiColor.YELLOW);
        }

        // Print requested HTTP GET response
        if (result.getHttpGetResponse() != null) {
            prettyAppendSubheading(builder, "Requested OCSP Response (HTTP GET)");
            prettyAppend(builder, result.getHttpGetResponse().toString(false));
        } else if (result.getHttpGetResponse() == null && result.getFirstResponse() != null) {
            prettyAppend(builder, "Retrieved an OCSP response via HTTP POST, but not via HTTP GET.", AnsiColor.YELLOW);
        }

        return builder;
    }

    private StringBuilder appendCertificateTransparency(StringBuilder builder) {
        prettyAppendHeading(builder, "Certificate Transparency");
        prettyAppend(builder, "Supports Precertificate SCTs", AnalyzedProperty.SUPPORTS_SCTS_PRECERTIFICATE);
        prettyAppend(builder, "Supports TLS Handshake SCTs", AnalyzedProperty.SUPPORTS_SCTS_HANDSHAKE);
        prettyAppend(builder, "Supports OCSP Response SCTs", AnalyzedProperty.SUPPORTS_SCTS_OCSP);
        prettyAppend(builder, "Meets Chrome's CT Policy", AnalyzedProperty.SUPPORTS_CHROME_CT_POLICY);

        if (report.getResult(AnalyzedProperty.SUPPORTS_SCTS_PRECERTIFICATE) == TestResult.TRUE) {
            prettyAppendSubheading(builder, "Precertificate SCTs");
            for (SignedCertificateTimestamp sct : report.getPrecertificateSctList().getCertificateTimestampList()) {
                prettyAppend(builder, sct.toString() + "\n");
            }
        }

        if (report.getResult(AnalyzedProperty.SUPPORTS_SCTS_HANDSHAKE) == TestResult.TRUE) {
            prettyAppendSubheading(builder, "TLS Handshake SCTs");
            for (SignedCertificateTimestamp sct : report.getHandshakeSctList().getCertificateTimestampList()) {
                prettyAppend(builder, sct.toString() + "\n");
            }
        }

        if (report.getResult(AnalyzedProperty.SUPPORTS_SCTS_OCSP) == TestResult.TRUE) {
            prettyAppendSubheading(builder, "OCSP Response SCTs");
            for (SignedCertificateTimestamp sct : report.getOcspSctList().getCertificateTimestampList()) {
                prettyAppend(builder, sct.toString() + "\n");
            }
        }

        return builder;
    }

    public StringBuilder appendSession(StringBuilder builder) {
        prettyAppendHeading(builder, "Session");
        prettyAppend(builder, "Supports Session Resumption", AnalyzedProperty.SUPPORTS_SESSION_IDS);
        prettyAppend(builder, "Supports Session Tickets", AnalyzedProperty.SUPPORTS_SESSION_TICKETS);
        prettyAppend(builder, "Issues TLS 1.3 Session Tickets", AnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS);
        prettyAppend(builder, "Supports TLS 1.3 PSK", AnalyzedProperty.SUPPORTS_TLS13_PSK);
        prettyAppend(builder, "Supports TLS 1.3 PSK-DHE", AnalyzedProperty.SUPPORTS_TLS13_PSK_DHE);
        prettyAppend(builder, "Supports 0-RTT", AnalyzedProperty.SUPPORTS_TLS13_0_RTT);
        // prettyAppend(builder, "Session Ticket Hint",
        // report.getSessionTicketLengthHint());
        // prettyAppendYellowOnFailure(builder, "Session Ticket Rotation",
        // report.getSessionTicketGetsRotated());
        // prettyAppendRedOnFailure(builder, "Ticketbleed",
        // report.getVulnerableTicketBleed());
        return builder;
    }

    public StringBuilder appendGcm(StringBuilder builder) {
        prettyAppendHeading(builder, "GCM");
        prettyAppend(builder, "GCM Nonce reuse", AnalyzedProperty.REUSES_GCM_NONCES);
        if (null == report.getGcmPattern()) {
            prettyAppend(builder, "GCM Pattern", (String) null);
        } else {
            switch (report.getGcmPattern()) {
                case AWKWARD:
                    prettyAppend(builder, "GCM Pattern", report.getGcmPattern().name(), AnsiColor.YELLOW);
                    break;
                case INCREMENTING:
                case RANDOM:
                    prettyAppend(builder, "GCM Pattern", report.getGcmPattern().name(), AnsiColor.GREEN);
                    break;
                case REPEATING:
                    prettyAppend(builder, "GCM Pattern", report.getGcmPattern().name(), AnsiColor.RED);
                    break;
                default:
                    prettyAppend(builder, "GCM Pattern", report.getGcmPattern().name(), AnsiColor.DEFAULT_COLOR);
                    break;
            }
        }
        prettyAppend(builder, "GCM Check", AnalyzedProperty.MISSES_GCM_CHECKS);
        return builder;
    }

    public StringBuilder appendRecordFragmentation(StringBuilder builder) {
        prettyAppendHeading(builder, "Record Fragmentation");
        prettyAppend(builder, "Supports Record Fragmentation", AnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION);
        return builder;
    }

    public StringBuilder appendIntolerances(StringBuilder builder) {
        prettyAppendHeading(builder, "Common Bugs [EXPERIMENTAL]");
        prettyAppend(builder, "Version Intolerant", AnalyzedProperty.HAS_VERSION_INTOLERANCE);
        prettyAppend(builder, "CipherSuite Intolerant", AnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE);
        prettyAppend(builder, "Extension Intolerant", AnalyzedProperty.HAS_EXTENSION_INTOLERANCE);
        prettyAppend(builder, "CS Length Intolerant (>512 Byte)", AnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE);
        prettyAppend(builder, "Compression Intolerant", AnalyzedProperty.HAS_COMPRESSION_INTOLERANCE);
        prettyAppend(builder, "ALPN Intolerant", AnalyzedProperty.HAS_ALPN_INTOLERANCE);
        prettyAppend(builder, "CH Length Intolerant", AnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE);
        prettyAppend(builder, "NamedGroup Intolerant", AnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE);
        prettyAppend(builder, "Empty last Extension Intolerant", AnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE);
        prettyAppend(builder, "SigHashAlgo Intolerant", AnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE);
        prettyAppend(builder, "Big ClientHello Intolerant", AnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE);
        prettyAppend(builder, "2nd CipherSuite Byte Bug", AnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG);
        prettyAppend(builder, "Ignores offered Cipher suites", AnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES);
        prettyAppend(builder, "Reflects offered Cipher suites", AnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES);
        prettyAppend(builder, "Ignores offered NamedGroups", AnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS);
        prettyAppend(builder, "Ignores offered SigHashAlgos", AnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS);
        prettyAppend(builder, "Grease CipherSuite Intolerant", AnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE);
        prettyAppend(builder, "Grease NamedGroup Intolerant", AnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE);
        prettyAppend(builder, "Grease SigHashAlgo Intolerant",
            AnalyzedProperty.HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE);
        return builder;
    }

    public StringBuilder appendHelloRetry(StringBuilder builder) {
        prettyAppendHeading(builder, "TLS 1.3 Hello Retry Request");
        prettyAppend(builder, "Sends Hello Retry Request", AnalyzedProperty.SENDS_HELLO_RETRY_REQUEST);
        prettyAppend(builder, "Issues Cookie", AnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY);
        return builder;
    }

    public StringBuilder appendAttackVulnerabilities(StringBuilder builder) {
        prettyAppendHeading(builder, "Attack Vulnerabilities");
        if (report.getKnownVulnerability() == null) {
            prettyAppend(builder, "Padding Oracle", AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE);
        } else {
            prettyAppend(builder, "Padding Oracle", "true - " + report.getKnownVulnerability().getShortName(),
                AnsiColor.RED);
        }
        prettyAppend(builder, "Bleichenbacher", AnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER);
        prettyAppend(builder, "Raccoon", AnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK);
        prettyAppend(builder, "Direct Raccoon", AnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON);
        prettyAppend(builder, "CRIME", AnalyzedProperty.VULNERABLE_TO_CRIME);
        prettyAppend(builder, "Breach", AnalyzedProperty.VULNERABLE_TO_BREACH);
        prettyAppend(builder, "Invalid Curve", AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE);
        prettyAppend(builder, "Invalid Curve (ephemeral)", AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL);
        prettyAppend(builder, "Invalid Curve (twist)", AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST);
        prettyAppend(builder, "SSL Poodle", AnalyzedProperty.VULNERABLE_TO_POODLE);
        prettyAppend(builder, "TLS Poodle", AnalyzedProperty.VULNERABLE_TO_TLS_POODLE);
        prettyAppend(builder, "Logjam", AnalyzedProperty.VULNERABLE_TO_LOGJAM);
        prettyAppend(builder, "Sweet 32", AnalyzedProperty.VULNERABLE_TO_SWEET_32);
        prettyAppend(builder, "General DROWN", AnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN);
        prettyAppend(builder, "Extra Clear DROWN", AnalyzedProperty.VULNERABLE_TO_EXTRA_CLEAR_DROWN);
        prettyAppend(builder, "Heartbleed", AnalyzedProperty.VULNERABLE_TO_HEARTBLEED);
        prettyAppend(builder, "EarlyCcs", AnalyzedProperty.VULNERABLE_TO_EARLY_CCS);
        prettyAppend(builder, "CVE-2020-13777 (Zero key)", AnalyzedProperty.VULNERABLE_TO_SESSION_TICKET_ZERO_KEY);
        prettyAppend(builder, "ALPACA", AnalyzedProperty.ALPACA_MITIGATED);
        prettyAppend(builder, "Renegotiation Attack (ext)",
            AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION);
        prettyAppend(builder, "Renegotiation Attack (cs)",
            AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE);

        return builder;
    }

    public StringBuilder appendRaccoonAttackDetails(StringBuilder builder) {
        DecimalFormat decimalFormat = new DecimalFormat();
        decimalFormat.setMaximumFractionDigits(24);
        if ((report.getResult(AnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK) == TestResult.TRUE
            || detail.isGreaterEqualTo(ScannerDetail.DETAILED)) && report.getRaccoonAttackProbabilities() != null) {
            prettyAppendHeading(builder, "Raccoon Attack Details");
            prettyAppend(builder,
                "Here we are calculating how likely it is that the attack can reach a critical block border.");
            prettyAppend(builder, "Available Injection points:", (long) report.getRaccoonAttackProbabilities().size());
            if (report.getRaccoonAttackProbabilities().size() > 0) {
                prettyAppendSubheading(builder, "Probabilities");
                prettyAppend(builder, addIndentations("InjectionPoint") + "\t Leak" + "\tProbability", AnsiColor.BOLD);
                for (RaccoonAttackProbabilities probabilities : report.getRaccoonAttackProbabilities()) {
                    builder.append(
                        addIndentations(probabilities.getPosition().name()) + "\t " + probabilities.getBitsLeaked()
                            + "\t" + decimalFormat.format(probabilities.getChanceForEquation()) + "\n");
                }
                if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_PSK_DHE) == TestResult.TRUE) {
                    prettyAppendSubheading(builder, "PSK Length Probabilities");
                    prettyAppend(builder, addIndentations("PSK Length") + addIndentations("BitLeak") + "Probability",
                        AnsiColor.BOLD);

                    for (RaccoonAttackProbabilities probabilities : report.getRaccoonAttackProbabilities()) {

                        prettyAppendSubheading(builder, probabilities.getPosition().name());

                        for (RaccoonAttackPskProbabilities pskProbability : probabilities.getPskProbabilityList()) {
                            prettyAppend(builder,
                                addIndentations("" + pskProbability.getPskLength())
                                    + addIndentations("" + pskProbability.getZeroBitsRequiredToNextBlockBorder())
                                    + decimalFormat.format(pskProbability.getChanceForEquation()));
                        }
                    }
                }

            }
        }
        return builder;
    }

    public StringBuilder appendInformationLeakTestList(StringBuilder builder,
        List<InformationLeakTest> informationLeakTestList, String heading) {
        prettyAppendHeading(builder, heading);
        if (informationLeakTestList == null || informationLeakTestList.isEmpty()) {
            prettyAppend(builder, "No test results");
        } else {
            for (InformationLeakTest testResult : informationLeakTestList) {
                String valueP;
                if (testResult.getValueP() >= 0.001) {
                    valueP = String.format("%.3f", testResult.getValueP());
                } else {
                    valueP = "<0.001";
                }
                String resultString = testResult.getTestInfo().getPrintableName();
                if (testResult.getValueP() < 0.01) {
                    prettyAppend(builder,
                        padToLength(resultString, 80) + " | " + padToLength(testResult.getEqualityError().name(), 25)
                            + padToLength("| VULNERABLE", 25) + "| P: " + valueP,
                        AnsiColor.RED);
                } else if (testResult.getValueP() < 0.05) {
                    prettyAppend(builder,
                        padToLength(resultString, 80) + " | " + padToLength(testResult.getEqualityError().name(), 25)
                            + padToLength("| PROBABLY VULNERABLE", 25) + "| P: " + valueP,
                        AnsiColor.YELLOW);
                } else if (testResult.getValueP() < 1) {
                    prettyAppend(builder,
                        padToLength(resultString, 80) + " | " + padToLength("No significant difference", 25)
                            + padToLength("| NOT VULNERABLE", 25) + "| P: " + valueP,
                        AnsiColor.GREEN);
                } else {
                    prettyAppend(builder,
                        padToLength(resultString, 80) + " | " + padToLength("No behavior difference", 25)
                            + padToLength("| NOT VULNERABLE", 25) + "| P: " + valueP,
                        AnsiColor.GREEN);
                }

                if ((detail == ScannerDetail.DETAILED
                    && Objects.equals(testResult.isSignificantDistinctAnswers(), Boolean.TRUE))
                    || detail == ScannerDetail.ALL) {
                    if (testResult.getEqualityError() != EqualityError.NONE || detail == ScannerDetail.ALL) {
                        prettyAppend(builder, "Response Map", AnsiColor.YELLOW);
                        appendInformationLeakTestResult(builder, testResult);
                    }
                }
            }

        }
        return builder;
    }

    public StringBuilder appendPaddingOracleResults(StringBuilder builder) {
        try {
            if (Objects.equals(report.getResult(AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE), TestResult.TRUE)) {
                prettyAppendHeading(builder, "PaddingOracle Details");

                if (report.getKnownVulnerability() != null) {
                    KnownPaddingOracleVulnerability knownVulnerability = report.getKnownVulnerability();
                    prettyAppend(builder, "Identification", knownVulnerability.getLongName(), AnsiColor.RED);
                    prettyAppend(builder, "CVE", knownVulnerability.getCve(), AnsiColor.RED);
                    if (knownVulnerability.getStrength() != PaddingOracleStrength.WEAK) {
                        prettyAppend(builder, "Strength", knownVulnerability.getStrength().name(), AnsiColor.RED);
                    } else {
                        prettyAppend(builder, "Strength", knownVulnerability.getStrength().name(), AnsiColor.YELLOW);
                    }
                    if (knownVulnerability.isObservable()) {
                        prettyAppend(builder, "Observable", "" + knownVulnerability.isObservable(), AnsiColor.RED);
                    } else {
                        prettyAppend(builder, "Observable", "" + knownVulnerability.isObservable(), AnsiColor.YELLOW);
                    }
                    prettyAppend(builder, "\n");
                    prettyAppend(builder, knownVulnerability.getDescription());
                    prettyAppendHeading(builder, "Affected Products");

                    for (String s : knownVulnerability.getAffectedProducts()) {
                        prettyAppend(builder, s, AnsiColor.YELLOW);
                    }
                    prettyAppend(builder, "");
                    prettyAppend(builder,
                        "If your tested software/hardware is not in this list, please let us know so we can add it here.");
                } else {
                    prettyAppend(builder, "Identification",
                        "Could not identify vulnerability. Please contact us if you know which software/hardware is generating this behavior.",
                        AnsiColor.YELLOW);
                }
            }
            prettyAppendHeading(builder, "PaddingOracle response map");
            if (report.getPaddingOracleTestResultList() == null || report.getPaddingOracleTestResultList().isEmpty()) {
                prettyAppend(builder, "No test results");
            } else {
                prettyAppend(builder, "No vulnerability present to identify");

                // TODO this recopying is weird
                List<InformationLeakTest> informationLeakTestList = new LinkedList<>();
                informationLeakTestList.addAll(report.getPaddingOracleTestResultList());
                appendInformationLeakTestList(builder, informationLeakTestList, "Padding Oracle Details");
            }
        } catch (Exception e) {
            prettyAppend(builder, "Error:" + e.getMessage());
        }
        return builder;
    }

    public StringBuilder appendInformationLeakTestResult(StringBuilder builder,
        InformationLeakTest informationLeakTest) {
        try {
            ResponseFingerprint defaultAnswer = informationLeakTest.retrieveMostCommonAnswer().getFingerprint();
            List<VectorContainer> vectorContainerList = informationLeakTest.getVectorContainerList();
            for (VectorContainer vectorContainer : vectorContainerList) {
                prettyAppend(builder, "\t" + padToLength(vectorContainer.getVector().getName(), 40));
                for (ResponseCounter counter : vectorContainer.getDistinctResponsesCounterList()) {
                    AnsiColor color = AnsiColor.GREEN;
                    if (!counter.getFingerprint().equals(defaultAnswer)) {
                        // TODO received app data should also make this red
                        color = AnsiColor.RED;
                    }
                    prettyAppend(builder,
                        "\t\t" + padToLength((counter.getFingerprint().toHumanReadable()), 40) + counter.getCounter()
                            + "/" + counter.getTotal() + " (" + String.format("%.2f", counter.getProbability() * 100)
                            + "%)",
                        color);

                }
            }
        } catch (Exception e) {
            prettyAppend(builder, "Error: " + e.getMessage());
        }
        return builder;
    }

    public StringBuilder appendBleichenbacherResults(StringBuilder builder) {
        try {
            prettyAppendHeading(builder, "Bleichenbacher response map");
            if (report.getBleichenbacherTestResultList() == null
                || report.getBleichenbacherTestResultList().isEmpty()) {
                prettyAppend(builder, "No test results");
            } else {
                prettyAppend(builder, "No vulnerability present to identify");

                // TODO this recopying is weird
                List<InformationLeakTest> informationLeakTestList = new LinkedList<>();
                informationLeakTestList.addAll(report.getBleichenbacherTestResultList());
                appendInformationLeakTestList(builder, informationLeakTestList, "Bleichenbacher Details");
            }
        } catch (Exception e) {
            prettyAppend(builder, "Error:" + e.getMessage());
        }
        return builder;
    }

    public StringBuilder appendEcPointFormats(StringBuilder builder) {
        prettyAppendHeading(builder, "Elliptic Curve Point Formats");
        prettyAppend(builder, "Uncompressed", AnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT);
        prettyAppend(builder, "ANSIX962 Prime", AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME);
        prettyAppend(builder, "ANSIX962 Char2", AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2);
        prettyAppend(builder, "TLS 1.3 ANSIX962  SECP", AnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION);
        return builder;
    }

    public StringBuilder appendInvalidCurveResults(StringBuilder builder) {
        prettyAppendHeading(builder, "Invalid Curve Details");
        boolean foundCouldNotTest = false;
        if (report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE) == TestResult.NOT_TESTED_YET
            && report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL) == TestResult.NOT_TESTED_YET
            && report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST) == TestResult.NOT_TESTED_YET) {
            prettyAppend(builder, "Not Tested");
        } else if (report.getInvalidCurveResultList() == null) {
            prettyAppend(builder, "No test results");
        } else if (report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE) == TestResult.FALSE
            && report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL) == TestResult.FALSE
            && report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST) == TestResult.FALSE
            && detail != ScannerDetail.ALL) {
            prettyAppend(builder, "No Vulnerabilities found");
        } else {
            for (InvalidCurveResponse response : report.getInvalidCurveResultList()) {
                if (response.getChosenGroupReusesKey() == TestResult.COULD_NOT_TEST
                    || response.getShowsVulnerability() == TestResult.COULD_NOT_TEST
                    || response.getShowsVulnerability() == TestResult.COULD_NOT_TEST) {
                    foundCouldNotTest = true;
                }
                if ((response.getShowsVulnerability() == TestResult.TRUE
                    && detail.isGreaterEqualTo(ScannerDetail.NORMAL))
                    || (response.getShowsPointsAreNotValidated() == TestResult.TRUE
                        && detail.isGreaterEqualTo(ScannerDetail.DETAILED))
                    || detail == ScannerDetail.ALL) {
                    prettyAppend(builder, response.getVector().toString());
                    switch (response.getShowsPointsAreNotValidated()) {
                        case TRUE:
                            prettyAppend(builder, "Server did not validate points", AnsiColor.YELLOW);
                            break;
                        case FALSE:
                            prettyAppend(builder, "Server did validate points / uses invulnerable algorithm",
                                AnsiColor.GREEN);
                            break;
                        default:
                            prettyAppend(builder, "Could not test point validation", AnsiColor.YELLOW);
                            break;
                    }
                    switch (response.getChosenGroupReusesKey()) {
                        case TRUE:
                            prettyAppend(builder, "Server did reuse key", AnsiColor.YELLOW);
                            break;
                        case FALSE:
                            prettyAppend(builder, "Server did not reuse key", AnsiColor.GREEN);
                            break;
                        default:
                            prettyAppend(builder, "Could not test key reuse", AnsiColor.YELLOW);
                            break;
                    }
                    switch (response.getShowsVulnerability()) {
                        case TRUE:
                            prettyAppend(builder, "Server is vulnerable", AnsiColor.RED);
                            break;
                        case FALSE:
                            prettyAppend(builder, "Server is not vulnerable", AnsiColor.GREEN);
                            break;
                        default:
                            prettyAppend(builder, "Could not test for vulnerability", AnsiColor.YELLOW);
                            break;
                    }
                    switch (response.getSideChannelSuspected()) {
                        case TRUE:
                            prettyAppend(builder, "Side Channel suspected", AnsiColor.RED);
                            break;
                        default:
                            prettyAppend(builder, "No Side Channel suspected", AnsiColor.GREEN);
                            break;
                    }

                }
            }

            if (foundCouldNotTest && detail.isGreaterEqualTo(ScannerDetail.NORMAL)) {
                prettyAppend(builder, "Some tests did not finish", AnsiColor.YELLOW);
            }
        }
        return builder;
    }

    public String toHumanReadable(ProtocolVersion version) {
        switch (version) {
            case DTLS10:
                return "DTLS 1.0";
            case DTLS12:
                return "DTLS 1.2";
            case SSL2:
                return "SSL 2.0";
            case SSL3:
                return "SSL 3.0";
            case TLS10:
                return "TLS 1.0";
            case TLS11:
                return "TLS 1.1";
            case TLS12:
                return "TLS 1.2";
            case TLS13:
                return "TLS 1.3";
            case TLS13_DRAFT14:
                return "TLS 1.3 Draft-14";
            case TLS13_DRAFT15:
                return "TLS 1.3 Draft-15";
            case TLS13_DRAFT16:
                return "TLS 1.3 Draft-16";
            case TLS13_DRAFT17:
                return "TLS 1.3 Draft-17";
            case TLS13_DRAFT18:
                return "TLS 1.3 Draft-18";
            case TLS13_DRAFT19:
                return "TLS 1.3 Draft-19";
            case TLS13_DRAFT20:
                return "TLS 1.3 Draft-20";
            case TLS13_DRAFT21:
                return "TLS 1.3 Draft-21";
            case TLS13_DRAFT22:
                return "TLS 1.3 Draft-22";
            case TLS13_DRAFT23:
                return "TLS 1.3 Draft-23";
            case TLS13_DRAFT24:
                return "TLS 1.3 Draft-24";
            case TLS13_DRAFT25:
                return "TLS 1.3 Draft-25";
            case TLS13_DRAFT26:
                return "TLS 1.3 Draft-26";
            case TLS13_DRAFT27:
                return "TLS 1.3 Draft-27";
            case TLS13_DRAFT28:
                return "TLS 1.3 Draft-28";
            default:
                return version.name();
        }
    }

    public StringBuilder appendCipherSuites(StringBuilder builder) {
        if (report.getCipherSuites() != null) {
            prettyAppendHeading(builder, "Supported Cipher suites");
            if (!report.getCipherSuites().isEmpty()) {
                for (CipherSuite suite : report.getCipherSuites()) {
                    builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
                }
            } else {
                prettyAppend(builder, "-empty-", AnsiColor.RED);
            }

            if (report.getVersionSuitePairs() != null && !report.getVersionSuitePairs().isEmpty()) {
                for (VersionSuiteListPair versionSuitePair : report.getVersionSuitePairs()) {
                    prettyAppendHeading(builder,
                        "Supported in " + toHumanReadable(versionSuitePair.getVersion())
                            + (report.getResult(AnalyzedProperty.ENFORCES_CS_ORDERING) == TestResult.TRUE
                                ? "(server order)" : ""));
                    for (CipherSuite suite : versionSuitePair.getCipherSuiteList()) {
                        builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
                    }
                }
            }

            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                prettyAppendHeading(builder, "Symmetric Supported");
                prettyAppend(builder, "Null", AnalyzedProperty.SUPPORTS_NULL_CIPHERS);
                prettyAppend(builder, "Export", AnalyzedProperty.SUPPORTS_EXPORT);
                prettyAppend(builder, "Anon", AnalyzedProperty.SUPPORTS_ANON);
                prettyAppend(builder, "DES", AnalyzedProperty.SUPPORTS_DES);
                prettyAppend(builder, "SEED", AnalyzedProperty.SUPPORTS_SEED);
                prettyAppend(builder, "IDEA", AnalyzedProperty.SUPPORTS_IDEA);
                prettyAppend(builder, "RC2", AnalyzedProperty.SUPPORTS_RC2);
                prettyAppend(builder, "RC4", AnalyzedProperty.SUPPORTS_RC4);
                prettyAppend(builder, "3DES", AnalyzedProperty.SUPPORTS_3DES);
                prettyAppend(builder, "AES", AnalyzedProperty.SUPPORTS_AES);
                prettyAppend(builder, "CAMELLIA", AnalyzedProperty.SUPPORTS_CAMELLIA);
                prettyAppend(builder, "ARIA", AnalyzedProperty.SUPPORTS_ARIA);
                prettyAppend(builder, "CHACHA20 POLY1305", AnalyzedProperty.SUPPORTS_CHACHA);

                prettyAppendHeading(builder, "KeyExchange Supported");
                prettyAppend(builder, "RSA", AnalyzedProperty.SUPPORTS_RSA);
                prettyAppend(builder, "DH", AnalyzedProperty.SUPPORTS_DH);
                prettyAppend(builder, "ECDH", AnalyzedProperty.SUPPORTS_ECDH);
                prettyAppend(builder, "GOST", AnalyzedProperty.SUPPORTS_GOST);
                // prettyAppend(builder, "SRP", report.getSupportsSrp());
                prettyAppend(builder, "Kerberos", AnalyzedProperty.SUPPORTS_KERBEROS);
                prettyAppend(builder, "Plain PSK", AnalyzedProperty.SUPPORTS_PSK_PLAIN);
                prettyAppend(builder, "PSK RSA", AnalyzedProperty.SUPPORTS_PSK_RSA);
                prettyAppend(builder, "PSK DHE", AnalyzedProperty.SUPPORTS_PSK_DHE);
                prettyAppend(builder, "PSK ECDHE", AnalyzedProperty.SUPPORTS_PSK_ECDHE);
                prettyAppend(builder, "Fortezza", AnalyzedProperty.SUPPORTS_FORTEZZA);
                prettyAppend(builder, "New Hope", AnalyzedProperty.SUPPORTS_NEWHOPE);
                prettyAppend(builder, "ECMQV", AnalyzedProperty.SUPPORTS_ECMQV);
                prettyAppend(builder, "TLS 1.3 PSK_DHE", AnalyzedProperty.SUPPORTS_TLS13_PSK_DHE);

                prettyAppendHeading(builder, "KeyExchange Signatures");
                prettyAppend(builder, "RSA", AnalyzedProperty.SUPPORTS_RSA_CERT);
                prettyAppend(builder, "ECDSA", AnalyzedProperty.SUPPORTS_ECDSA);
                prettyAppend(builder, "DSS", AnalyzedProperty.SUPPORTS_DSS);

                prettyAppendHeading(builder, "Cipher Types Supports");
                prettyAppend(builder, "Stream", AnalyzedProperty.SUPPORTS_STREAM_CIPHERS);
                prettyAppend(builder, "Block", AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS);
                prettyAppend(builder, "AEAD", AnalyzedProperty.SUPPORTS_AEAD);
            }
            prettyAppendHeading(builder, "Perfect Forward Secrecy");
            prettyAppend(builder, "Supports PFS", AnalyzedProperty.SUPPORTS_PFS);
            prettyAppend(builder, "Prefers PFS", AnalyzedProperty.PREFERS_PFS);
            prettyAppend(builder, "Supports Only PFS", AnalyzedProperty.SUPPORTS_ONLY_PFS);

            prettyAppendHeading(builder, "CipherSuite General");
            prettyAppend(builder, "Enforces CipherSuite ordering", AnalyzedProperty.ENFORCES_CS_ORDERING);
        }
        return builder;
    }

    public StringBuilder appendProtocolVersions(StringBuilder builder) {
        if (report.getVersions() != null) {
            prettyAppendHeading(builder, "Versions");
            prettyAppend(builder, "DTLS 1.0", AnalyzedProperty.SUPPORTS_DTLS_1_0);
            prettyAppend(builder, "DTLS 1.2", AnalyzedProperty.SUPPORTS_DTLS_1_2);
            prettyAppend(builder, "SSL 2.0", AnalyzedProperty.SUPPORTS_SSL_2);
            prettyAppend(builder, "SSL 3.0", AnalyzedProperty.SUPPORTS_SSL_3);
            prettyAppend(builder, "TLS 1.0", AnalyzedProperty.SUPPORTS_TLS_1_0);
            prettyAppend(builder, "TLS 1.1", AnalyzedProperty.SUPPORTS_TLS_1_1);
            prettyAppend(builder, "TLS 1.2", AnalyzedProperty.SUPPORTS_TLS_1_2);
            prettyAppend(builder, "TLS 1.3", AnalyzedProperty.SUPPORTS_TLS_1_3);
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 14", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 15", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 16", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 17", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 18", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 19", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 20", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 21", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 22", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 23", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 24", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 25", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 26", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 27", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 28", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28);
            }
        }
        return builder;
    }

    public StringBuilder appendHttps(StringBuilder builder) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_HTTPS) == TestResult.TRUE) {
            prettyAppendHeading(builder, "HSTS");
            try {

                if (report.getResult(AnalyzedProperty.SUPPORTS_HSTS) == TestResult.TRUE) {
                    prettyAppend(builder, "HSTS", AnalyzedProperty.SUPPORTS_HSTS);
                    prettyAppend(builder, "HSTS Preloading", AnalyzedProperty.SUPPORTS_HSTS_PRELOADING);
                    prettyAppend(builder, "max-age (seconds)", (long) report.getHstsMaxAge());
                } else {
                    prettyAppend(builder, "Not supported");
                }
                prettyAppendHeading(builder, "HPKP");
                if (report.getResult(AnalyzedProperty.SUPPORTS_HPKP) == TestResult.TRUE
                    || report.getResult(AnalyzedProperty.SUPPORTS_HPKP_REPORTING) == TestResult.TRUE) {
                    prettyAppend(builder, "HPKP", AnalyzedProperty.SUPPORTS_HPKP);
                    prettyAppend(builder, "HPKP (report only)", AnalyzedProperty.SUPPORTS_HPKP_REPORTING);
                    prettyAppend(builder, "max-age (seconds)", (long) report.getHpkpMaxAge());
                    if (report.getNormalHpkpPins().size() > 0) {
                        prettyAppend(builder, "");
                        prettyAppend(builder, "HPKP-Pins:", AnsiColor.GREEN);
                        for (HpkpPin pin : report.getNormalHpkpPins()) {
                            prettyAppend(builder, pin.toString());
                        }
                    }
                    if (report.getReportOnlyHpkpPins().size() > 0) {
                        prettyAppend(builder, "");
                        prettyAppend(builder, "Report Only HPKP-Pins:", AnsiColor.GREEN);
                        for (HpkpPin pin : report.getReportOnlyHpkpPins()) {
                            prettyAppend(builder, pin.toString());
                        }
                    }

                } else {
                    prettyAppend(builder, "Not supported");
                }
                prettyAppendHeading(builder, "HTTPS Response Header");
                for (HttpsHeader header : report.getHeaderList()) {
                    prettyAppend(builder, header.getHeaderName().getValue() + ":" + header.getHeaderValue().getValue());
                }
                prettyAppendHeading(builder, "HTTP False Start");
                prettyAppend(builder, "HTTP False Start", AnalyzedProperty.SUPPORTS_HTTP_FALSE_START);
            } catch (Exception e) {
                prettyAppend(builder, "Error: " + e.getMessage());
            }
        }

        return builder;
    }

    public StringBuilder appendExtensions(StringBuilder builder) {
        if (report.getSupportedExtensions() != null) {
            prettyAppendHeading(builder, "Supported Extensions");
            for (ExtensionType type : report.getSupportedExtensions()) {
                builder.append(type.name()).append("\n");
            }
        }
        prettyAppendHeading(builder, "Extensions");
        prettyAppend(builder, "Secure Renegotiation", AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION);
        prettyAppend(builder, "Extended Master Secret", AnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET);
        prettyAppend(builder, "Encrypt Then Mac", AnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC);
        prettyAppend(builder, "Tokenbinding", AnalyzedProperty.SUPPORTS_TOKENBINDING);
        prettyAppend(builder, "Certificate Status Request", AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST);
        prettyAppend(builder, "Certificate Status Request v2", AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2);
        prettyAppend(builder, "ESNI", AnalyzedProperty.SUPPORTS_ESNI);

        if (report.getResult(AnalyzedProperty.SUPPORTS_TOKENBINDING) == TestResult.TRUE) {
            prettyAppendHeading(builder, "Tokenbinding Version");
            for (TokenBindingVersion version : report.getSupportedTokenBindingVersion()) {
                builder.append(version.toString()).append("\n");
            }

            prettyAppendHeading(builder, "Tokenbinding Key Parameters");
            for (TokenBindingKeyParameters keyParameter : report.getSupportedTokenBindingKeyParameters()) {
                builder.append(keyParameter.toString()).append("\n");
            }
        }
        appendTls13Groups(builder);
        appendCurves(builder);
        appendSignatureAndHashAlgorithms(builder);
        return builder;
    }

    public StringBuilder appendAlpacaAttack(StringBuilder builder) {
        prettyAppendHeading(builder, "Alpaca Details");
        prettyAppend(builder, "Strict ALPN", AnalyzedProperty.STRICT_ALPN);
        prettyAppend(builder, "Strict SNI", AnalyzedProperty.STRICT_SNI);
        prettyAppend(builder, "ALPACA Mitigation", AnalyzedProperty.ALPACA_MITIGATED);
        return builder;
    }

    public StringBuilder appendAlpn(StringBuilder builder) {
        if (report.getSupportedAlpns() != null) {
            prettyAppendHeading(builder, "ALPN");
            for (AlpnProtocol alpnProtocol : AlpnProtocol.values()) {
                if (alpnProtocol.isGrease()) {
                    continue;
                }
                if (report.getSupportedAlpns().contains(alpnProtocol.getConstant())) {
                    prettyAppend(builder, alpnProtocol.getPrintableName(), true);
                } else {
                    if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                        prettyAppend(builder, alpnProtocol.getPrintableName(), false);
                    }
                }
            }
        }
        return builder;
    }

    public void appendRandom(StringBuilder builder) {
        prettyAppendHeading(builder, "Nonce");
        prettyAppendRandom(builder, "Random", report.getRandomEvaluationResult());
    }

    public void appendPublicKeyIssues(StringBuilder builder) {
        prettyAppendHeading(builder, "PublicKey Parameter");
        prettyAppend(builder, "EC PublicKey reuse", AnalyzedProperty.REUSES_EC_PUBLICKEY);
        prettyAppend(builder, "DH PublicKey reuse", AnalyzedProperty.REUSES_DH_PUBLICKEY);
        prettyAppend(builder, "Uses Common DH Primes", AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES);
        if (report.getUsedCommonDhValueList() != null && report.getUsedCommonDhValueList().size() != 0) {
            for (CommonDhValues value : report.getUsedCommonDhValueList()) {
                prettyAppend(builder, "\t" + value.getName(), AnsiColor.YELLOW);
            }
        }
        prettyAppend(builder, "Uses only prime moduli", AnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI);
        prettyAppend(builder, "Uses only safe-prime moduli", AnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI);
        if (report.getWeakestDhStrength() != null) {
            if (report.getWeakestDhStrength() < 1000) {
                prettyAppend(builder, "DH Strength", "" + report.getWeakestDhStrength(), AnsiColor.RED);
            } else if (report.getWeakestDhStrength() < 2000) {
                prettyAppend(builder, "DH Strength", "" + report.getWeakestDhStrength(), AnsiColor.YELLOW);
            } else if (report.getWeakestDhStrength() < 4100) {
                prettyAppend(builder, "DH Strength", "" + report.getWeakestDhStrength(), AnsiColor.GREEN);
            } else {
                prettyAppend(builder, "DH Strength", "" + report.getWeakestDhStrength(), AnsiColor.YELLOW);
            }
        }
    }

    public void appendScoringResults(StringBuilder builder) {
        prettyAppendHeading(builder, "Scoring results");

        SiteReportRater rater;
        try {
            rater = SiteReportRater.getSiteReportRater("en");
            ScoreReport scoreReport = rater.getScoreReport(report.getResultMap());
            prettyAppend(builder, "Score: " + scoreReport.getScore());
            if (!detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                return;
            }
            prettyAppend(builder, "");
            scoreReport.getInfluencers().entrySet().forEach((entry) -> {
                PropertyResultRatingInfluencer influencer = entry.getValue();
                Recommendation recommendation = rater.getRecommendations().getRecommendation(entry.getKey());
                int scoreInfluence = 0;
                StringBuilder additionalInfo = new StringBuilder();
                if (influencer.getReferencedProperty() != null) {
                    additionalInfo.append(" (Score: 0). -> See ").append(influencer.getReferencedProperty())
                        .append(" for more information");
                } else {
                    scoreInfluence = influencer.getInfluence();
                    additionalInfo.append(" (Score: ").append((scoreInfluence > 0 ? "+" : "")).append(scoreInfluence);
                    if (influencer.hasScoreCap()) {
                        additionalInfo.append(", Score cap: ").append(influencer.getScoreCap());
                    }
                    additionalInfo.append(")");
                }
                String result = recommendation.getShortName() + ": " + influencer.getResult() + additionalInfo;
                if (scoreInfluence > 0) {
                    prettyAppend(builder, result, AnsiColor.GREEN);
                } else if (scoreInfluence < -50) {
                    prettyAppend(builder, result, AnsiColor.RED);
                } else if (scoreInfluence < 0) {
                    prettyAppend(builder, result, AnsiColor.YELLOW);
                }
            });
        } catch (JAXBException ex) {
            prettyAppend(builder, "Could not append scoring results", AnsiColor.RED);
            prettyAppend(builder, ex.getLocalizedMessage(), AnsiColor.RED);
        }
    }

    public void appendRecommendations(StringBuilder builder) {
        prettyAppendHeading(builder, "Recommendations");

        SiteReportRater rater;
        try {
            rater = SiteReportRater.getSiteReportRater("en");
            ScoreReport scoreReport = rater.getScoreReport(report.getResultMap());
            LinkedHashMap<AnalyzedProperty, PropertyResultRatingInfluencer> influencers = scoreReport.getInfluencers();
            influencers.entrySet().stream().sorted((o1, o2) -> {
                return o1.getValue().compareTo(o2.getValue());
            }).forEach((entry) -> {
                PropertyResultRatingInfluencer influencer = entry.getValue();
                if (influencer.isBadInfluence() || influencer.getReferencedProperty() != null) {
                    Recommendation recommendation = rater.getRecommendations().getRecommendation(entry.getKey());
                    PropertyResultRecommendation resultRecommendation =
                        recommendation.getPropertyResultRecommendation(influencer.getResult());
                    if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                        printFullRecommendation(builder, rater, recommendation, influencer, resultRecommendation);
                    } else {
                        printShortRecommendation(builder, influencer, resultRecommendation);
                    }
                }
            });
        } catch (Exception ex) {
            prettyAppend(builder, "Could not append recommendations - unrelated error", AnsiColor.RED);
            LOGGER.error("Could not append recommendations", ex);
        }
    }

    private void printFullRecommendation(StringBuilder builder, SiteReportRater rater, Recommendation recommendation,
        PropertyResultRatingInfluencer influencer, PropertyResultRecommendation resultRecommendation) {
        AnsiColor color = getRecommendationColor(influencer);
        prettyAppend(builder, "", color);
        prettyAppend(builder, recommendation.getShortName() + ": " + influencer.getResult(), color);
        int scoreInfluence = 0;
        String additionalInfo = "";
        if (influencer.getReferencedProperty() != null) {
            scoreInfluence =
                rater.getRatingInfluencers().getPropertyRatingInfluencer(influencer.getReferencedProperty(),
                    influencer.getReferencedPropertyResult()).getInfluence();
            Recommendation r = rater.getRecommendations().getRecommendation(influencer.getReferencedProperty());
            additionalInfo = " -> This score comes from \"" + r.getShortName() + "\"";
        } else {
            scoreInfluence = influencer.getInfluence();
        }
        prettyAppend(builder, "  Score: " + scoreInfluence + additionalInfo, color);
        if (influencer.hasScoreCap()) {
            prettyAppend(builder, "  Score cap: " + influencer.getScoreCap(), color);
        }
        prettyAppend(builder, "  Information: " + resultRecommendation.getShortDescription(), color);
        prettyAppend(builder, "  Recommendation: " + resultRecommendation.getHandlingRecommendation(), color);
    }

    private void printShortRecommendation(StringBuilder builder, PropertyResultRatingInfluencer influencer,
        PropertyResultRecommendation resultRecommendation) {
        AnsiColor color = getRecommendationColor(influencer);
        prettyAppend(builder,
            resultRecommendation.getShortDescription() + ". " + resultRecommendation.getHandlingRecommendation(),
            color);
    }

    private AnsiColor getRecommendationColor(PropertyResultRatingInfluencer influencer) {
        if (influencer.getInfluence() <= -200) {
            return AnsiColor.RED;
        } else if (influencer.getInfluence() < -50) {
            return AnsiColor.YELLOW;
        } else if (influencer.getInfluence() > 0) {
            return AnsiColor.GREEN;
        }
        return AnsiColor.DEFAULT_COLOR;
    }

    private void prettyPrintCipherSuite(StringBuilder builder, CipherSuite suite) {
        CipherSuiteGrade grade = CipherSuiteRater.getGrade(suite);
        switch (grade) {
            case GOOD:
                prettyAppend(builder, suite.name(), AnsiColor.GREEN);
                break;
            case LOW:
                prettyAppend(builder, suite.name(), AnsiColor.RED);
                break;
            case MEDIUM:
                prettyAppend(builder, suite.name(), AnsiColor.YELLOW);
                break;
            case NONE:
                prettyAppend(builder, suite.name());
                break;
            default:
                prettyAppend(builder, suite.name());
        }
    }

    public StringBuilder appendCurves(StringBuilder builder) {
        if (report.getSupportedNamedGroups() != null) {
            prettyAppendHeading(builder, "Supported Named Groups");
            if (report.getSupportedNamedGroups().size() > 0) {
                for (NamedGroup group : report.getSupportedNamedGroups()) {
                    builder.append(group.name());
                    if (detail == ScannerDetail.ALL) {
                        builder.append("\n  Found using:");
                        NamedCurveWitness witness = report.getSupportedNamedGroupsWitnesses().get(group);
                        for (CipherSuite cipher : witness.getCipherSuites()) {
                            builder.append("\n    ").append(cipher.toString());
                        }
                        builder.append("\n  ECDSA Required Groups:");
                        if (witness.getEcdsaPkGroupEphemeral() != null && witness.getEcdsaPkGroupEphemeral() != group) {
                            builder.append("\n    ").append(witness.getEcdsaPkGroupEphemeral())
                                .append(" (Certificate Public Key - Ephemeral Cipher Suite)");
                        }
                        if (witness.getEcdsaSigGroupEphemeral() != null
                            && witness.getEcdsaSigGroupEphemeral() != group) {
                            builder.append("\n    ").append(witness.getEcdsaSigGroupEphemeral())
                                .append(" (Certificate Signature  - Ephemeral Cipher Suite)");
                        }
                        if (witness.getEcdsaSigGroupStatic() != null && witness.getEcdsaSigGroupStatic() != group) {
                            builder.append("\n    ").append(witness.getEcdsaSigGroupStatic())
                                .append(" (Certificate Signature  - Static Cipher Suite)");
                        }
                    }
                    builder.append("\n");
                }
                if (report.getResult(AnalyzedProperty.GROUPS_DEPEND_ON_CIPHER) == TestResult.TRUE) {
                    prettyAppend(builder, "Not all Groups are supported for all Cipher Suites");
                }
                if (report.getResult(AnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY) == TestResult.TRUE) {
                    prettyAppend(builder, "Groups required for ECDSA validation are not enforced", AnsiColor.YELLOW);
                }
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    public StringBuilder appendSignatureAndHashAlgorithms(StringBuilder builder) {
        if (report.getSupportedSignatureAndHashAlgorithms() != null) {
            prettyAppendHeading(builder, "Supported Signature and Hash Algorithms");
            if (report.getSupportedSignatureAndHashAlgorithms().size() > 0) {
                for (SignatureAndHashAlgorithm algorithm : report.getSupportedSignatureAndHashAlgorithms()) {
                    prettyAppend(builder, algorithm.toString());
                }
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    public StringBuilder appendCompressions(StringBuilder builder) {
        if (report.getSupportedCompressionMethods() != null) {
            prettyAppendHeading(builder, "Supported Compressions");
            for (CompressionMethod compression : report.getSupportedCompressionMethods()) {
                prettyAppend(builder, compression.name());
            }
        }
        return builder;
    }

    private String getBlackString(String value, String format) {
        return String.format(format, value == null ? "Unknown" : value);
    }

    private String getGreenString(String value, String format) {
        return (printColorful ? AnsiColor.GREEN.getCode() : AnsiColor.RESET.getCode())
            + String.format(format, value == null ? "Unknown" : value) + AnsiColor.RESET.getCode();
    }

    private String getYellowString(String value, String format) {
        return (printColorful ? AnsiColor.YELLOW.getCode() : AnsiColor.RESET.getCode())
            + String.format(format, value == null ? "Unknown" : value) + AnsiColor.RESET.getCode();
    }

    private String getRedString(String value, String format) {
        return (printColorful ? AnsiColor.RED.getCode() : AnsiColor.RESET.getCode())
            + String.format(format, value == null ? "Unknown" : value) + AnsiColor.RESET.getCode();
    }

    private StringBuilder prettyAppend(StringBuilder builder, String value) {
        return builder.append(value == null ? "Unknown" : value).append("\n");
    }

    private StringBuilder prettyAppend(StringBuilder builder, String value, AnsiColor color) {
        if (printColorful) {
            builder.append(color.getCode());
        }
        builder.append(value);
        if (printColorful) {
            builder.append(AnsiColor.RESET.getCode());
        }
        builder.append("\n");
        return builder;
    }

    private StringBuilder prettyAppend(StringBuilder builder, String name, String value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : value)
            .append("\n");
    }

    private StringBuilder prettyAppend(StringBuilder builder, String name, Long value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : value)
            .append("\n");
    }

    private StringBuilder prettyAppend(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : value)
            .append("\n");
    }

    private StringBuilder prettyAppend(StringBuilder builder, String name, AnalyzedProperty property) {
        builder.append(addIndentations(name)).append(": ");
        builder.append(scheme.getEncodedString(report, property));
        builder.append("\n");
        return builder;
    }

    private StringBuilder prettyAppend(StringBuilder builder, String name, Boolean value, AnsiColor color) {
        return prettyAppend(builder, name, "" + value, color);
    }

    private StringBuilder prettyAppend(StringBuilder builder, String name, String value, AnsiColor color) {
        builder.append(addIndentations(name)).append(": ");
        if (printColorful) {
            builder.append(color.getCode());
        }
        builder.append(value);
        if (printColorful) {
            builder.append(AnsiColor.RESET.getCode());
        }
        builder.append("\n");
        return builder;
    }

    private StringBuilder prettyAppendHeading(StringBuilder builder, String value) {
        depth = 0;

        return builder
            .append(printColorful ? AnsiColor.BOLD.getCode() + AnsiColor.BLUE.getCode() : AnsiColor.RESET.getCode())
            .append("\n------------------------------------------------------------\n").append(value).append("\n\n")
            .append(AnsiColor.RESET.getCode());
    }

    private StringBuilder prettyAppendUnderlined(StringBuilder builder, String name, String value) {
        return builder.append(addIndentations(name)).append(": ")
            .append((printColorful ? AnsiColor.UNDERLINE.getCode() + value + AnsiColor.RESET.getCode() : value))
            .append("\n");
    }

    private StringBuilder prettyAppendUnderlined(StringBuilder builder, String name, boolean value) {
        return builder.append(addIndentations(name)).append(": ")
            .append((printColorful ? AnsiColor.UNDERLINE.getCode() + value + AnsiColor.RESET.getCode() : value))
            .append("\n");
    }

    private StringBuilder prettyAppendUnderlined(StringBuilder builder, String name, long value) {
        return builder.append(addIndentations(name)).append(": ")
            .append(
                (printColorful == false ? AnsiColor.UNDERLINE.getCode() + value + AnsiColor.RESET.getCode() : value))
            .append("\n");
    }

    private StringBuilder prettyAppendSubheading(StringBuilder builder, String name) {
        depth = 1;
        return builder.append("--|").append(printColorful ? AnsiColor.BOLD.getCode() + AnsiColor.PURPLE.getCode()
            + AnsiColor.UNDERLINE.getCode() + name + "\n\n" + AnsiColor.RESET.getCode() : name + "\n\n");
    }

    private StringBuilder prettyAppendSubSubheading(StringBuilder builder, String name) {
        depth = 2;
        return builder.append("----|").append(printColorful ? AnsiColor.BOLD.getCode() + AnsiColor.PURPLE.getCode()
            + AnsiColor.UNDERLINE.getCode() + name + "\n\n" + AnsiColor.RESET.getCode() : name + "\n\n");
    }

    private StringBuilder prettyAppendSubSubSubheading(StringBuilder builder, String name) {
        depth = 3;
        return builder.append("------|").append(printColorful ? AnsiColor.BOLD.getCode() + AnsiColor.PURPLE.getCode()
            + AnsiColor.UNDERLINE.getCode() + name + "\n\n" + AnsiColor.RESET.getCode() : name + "\n\n");
    }

    private void prettyAppendEarlyCcs(StringBuilder builder, String testName,
        EarlyCcsVulnerabilityType earlyCcsVulnerable) {
        builder.append(addIndentations(testName)).append(": ");
        if (earlyCcsVulnerable == null) {
            prettyAppend(builder, "Unknown");
            return;
        }
        switch (earlyCcsVulnerable) {
            case VULN_EXPLOITABLE:
                prettyAppend(builder, "true - exploitable", AnsiColor.RED);
                break;
            case VULN_NOT_EXPLOITABLE:
                prettyAppend(builder, "true - probably not exploitable", AnsiColor.RED);
                break;
            case NOT_VULNERABLE:
                prettyAppend(builder, "false", AnsiColor.GREEN);
                break;
            case UNKNOWN:
                prettyAppend(builder, "Unknown");
                break;
            default:
                prettyAppend(builder, "Unknown");
                break;
        }
    }

    private StringBuilder prettyAppendCheckPattern(StringBuilder builder, String value, CheckPattern pattern) {
        if (pattern == null) {
            return builder.append(addIndentations(value)).append(": ").append("Unknown").append("\n");
        }
        builder = builder.append(addIndentations(value)).append(": ");
        switch (pattern.getType()) {
            case CORRECT:
                return prettyAppend(builder, pattern.toString(), AnsiColor.GREEN);
            case NONE:
            case PARTIAL:
                return prettyAppend(builder, pattern.toString(), AnsiColor.RED);
            case UNKNOWN:
                return prettyAppend(builder, pattern.toString());
            default:
                throw new IllegalArgumentException("Unknown MacCheckPattern Type: " + pattern.getType());
        }
    }

    private String padToLength(String value, int length) {
        StringBuilder builder = new StringBuilder(value);
        while (builder.length() < length) {
            builder.append(" ");
        }
        return builder.toString();
    }

    private String addIndentations(String value) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            builder.append(" ");
        }
        builder.append(value);
        if (value.length() + depth < 8) {
            builder.append("\t\t\t\t ");
        } else if (value.length() + depth < 16) {
            builder.append("\t\t\t ");
        } else if (value.length() + depth < 24) {
            builder.append("\t\t ");
        } else if (value.length() + depth < 32) {
            builder.append("\t ");
        } else {
            builder.append(" ");
        }
        return builder.toString();
    }

    public StringBuilder appendTls13Groups(StringBuilder builder) {
        if (report.getSupportedTls13Groups() != null) {
            prettyAppendHeading(builder, "TLS 1.3 Named Groups");
            if (report.getSupportedTls13Groups().size() > 0) {
                for (NamedGroup group : report.getSupportedTls13Groups()) {
                    builder.append(group.name()).append("\n");
                }
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    private void prettyAppendRandom(StringBuilder builder, String testName,
        RandomEvaluationResult randomEvaluationResult) {
        if (randomEvaluationResult == null) {
            prettyAppend(builder, testName, "unknown", AnsiColor.DEFAULT_COLOR);
            return;
        }
        switch (randomEvaluationResult) {
            case DUPLICATES:
                prettyAppend(builder, testName, "true - exploitable", AnsiColor.RED);
                break;
            case NOT_ANALYZED:
                prettyAppend(builder, testName, "not analyzed", AnsiColor.DEFAULT_COLOR);
                break;
            case NOT_RANDOM:
                prettyAppend(builder, testName, "does not seem to be random", AnsiColor.DEFAULT_COLOR);
                break;
            case UNIX_TIME:
                prettyAppend(builder, testName, "contains unix time", AnsiColor.DEFAULT_COLOR);
                break;
            case NO_DUPLICATES:
                prettyAppend(builder, testName, "no duplicates (wip)", AnsiColor.GREEN);
                break;
            default:
                ;
        }
    }

    private void prettyAppendCookie(StringBuilder builder, String testName,
        CookieEvaluationResult cookieEvaluationResult) {
        if (cookieEvaluationResult == null) {
            prettyAppend(builder, testName, "unknown", AnsiColor.DEFAULT_COLOR);
            return;
        }
        switch (cookieEvaluationResult) {
            case DUPLICATES:
                prettyAppend(builder, testName, "duplicates", AnsiColor.RED);
                break;
            case NOT_ANALYZED:
                prettyAppend(builder, testName, "not analyzed", AnsiColor.DEFAULT_COLOR);
                break;
            case NO_DUPLICATES:
                prettyAppend(builder, testName, "no duplicates", AnsiColor.GREEN);
                break;
        }
    }

    public void setDepth(int depth) {
        this.depth = depth;
    }

    public void appendPerformanceData(StringBuilder builder) {
        if (detail.isGreaterEqualTo(ScannerDetail.ALL)) {
            prettyAppendHeading(builder, "Scanner Performance");
            try {
                prettyAppend(builder, "TCP connections", "" + report.getPerformedTcpConnections());
                prettyAppendSubheading(builder, "Probe execution performance");
                for (PerformanceData data : report.getPerformanceList()) {
                    SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
                    Duration duration = new Duration(data.getStartTime(), data.getStopTime());
                    Period period = new Period(data.getStopTime() - data.getStartTime());
                    prettyAppend(builder,
                        padToLength(data.getType().name(), 25) + " " + PeriodFormat.getDefault().print(period));

                }
            } catch (Exception e) {
                prettyAppend(builder, "Error: " + e.getMessage());
            }
        } else {
            LOGGER.debug("Not printing performance data.");
        }
    }

    private void appendClientAuthentication(StringBuilder builder) {
        prettyAppendHeading(builder, "Client authentication");
        prettyAppend(builder, "Supported", report.getCcaSupported());
        prettyAppend(builder, "Required", report.getCcaRequired());

        if (report.getCcaTestResultList() != null) {
            List<CcaTestResult> ccaTestResults = report.getCcaTestResultList();
            ccaTestResults.sort(new Comparator<CcaTestResult>() {
                @Override
                public int compare(CcaTestResult ccaTestResult, CcaTestResult t1) {
                    int c;
                    c = ccaTestResult.getWorkflowType().compareTo(t1.getWorkflowType());
                    if (c != 0) {
                        return c;
                    }

                    c = ccaTestResult.getCertificateType().compareTo(t1.getCertificateType());
                    if (c != 0) {
                        return c;
                    }

                    c = ccaTestResult.getProtocolVersion().compareTo(t1.getProtocolVersion());
                    if (c != 0) {
                        return c;
                    }

                    c = ccaTestResult.getCipherSuite().compareTo(t1.getCipherSuite());
                    return c;
                }
            });
            CcaWorkflowType lastCcaWorkflowType = null;
            CcaCertificateType lastCcaCertificateType = null;
            ProtocolVersion lastProtocolVersion = null;
            for (CcaTestResult ccaTestResult : ccaTestResults) {
                if (ccaTestResult.getWorkflowType() != lastCcaWorkflowType) {
                    lastCcaWorkflowType = ccaTestResult.getWorkflowType();
                    prettyAppendSubheading(builder, lastCcaWorkflowType.name());
                }
                if (ccaTestResult.getCertificateType() != lastCcaCertificateType) {
                    lastCcaCertificateType = ccaTestResult.getCertificateType();
                    prettyAppendSubSubheading(builder, lastCcaCertificateType.name());
                }
                if (ccaTestResult.getProtocolVersion() != lastProtocolVersion) {
                    lastProtocolVersion = ccaTestResult.getProtocolVersion();
                    prettyAppendSubSubSubheading(builder, lastProtocolVersion.name());
                }
                prettyAppend(builder,
                    ccaTestResult.getWorkflowType().name().concat("--")
                        .concat(ccaTestResult.getCertificateType().name()).concat("--")
                        .concat(ccaTestResult.getProtocolVersion().name()).concat("--")
                        .concat(ccaTestResult.getCipherSuite().name()),
                    ccaTestResult.getSucceeded(), ccaTestResult.getSucceeded() ? AnsiColor.RED : AnsiColor.GREEN);

            }
        }
    }

    private StringBuilder sessionTicketZeroKeyDetails(StringBuilder builder) {

        if (report.getResult(AnalyzedProperty.VULNERABLE_TO_SESSION_TICKET_ZERO_KEY) == TestResult.TRUE) {
            prettyAppendHeading(builder, "Session Ticket Zero Key Attack Details");
            prettyAppend(builder, "Has GnuTls magic bytes:", AnalyzedProperty.HAS_GNU_TLS_MAGIC_BYTES);
        }
        return builder;
    }
}
