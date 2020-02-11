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
import static de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType.NOT_VULNERABLE;
import static de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType.VULN_EXPLOITABLE;
import static de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType.VULN_NOT_EXPLOITABLE;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.pkcs1.VectorFingerprintPair;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsscanner.constants.AnsiColor;
import de.rub.nds.tlsscanner.constants.CipherSuiteGrade;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.probe.certificate.CertificateIssue;
import de.rub.nds.tlsscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.probe.directRaccoon.DirectRaccoonCipherSuiteFingerprint;
import de.rub.nds.tlsscanner.probe.directRaccoon.DirectRaccoonVectorResponse;
import de.rub.nds.tlsscanner.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.probe.padding.PaddingOracleStrength;
import de.rub.nds.tlsscanner.report.after.prime.CommonDhValues;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.ConnectionInsecure;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.HandshakeFailureReasons;
import de.rub.nds.tlsscanner.rating.PropertyResultRatingInfluencer;
import de.rub.nds.tlsscanner.rating.PropertyResultRecommendation;
import de.rub.nds.tlsscanner.rating.Recommendation;
import de.rub.nds.tlsscanner.rating.ScoreReport;
import de.rub.nds.tlsscanner.rating.SiteReportRater;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.after.padding.ShakyEvaluationReport;
import de.rub.nds.tlsscanner.report.after.padding.ShakyVectorHolder;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.bleichenbacher.BleichenbacherTestResult;
import de.rub.nds.tlsscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleCipherSuiteFingerprint;
import de.rub.nds.tlsscanner.report.result.statistics.RandomEvaluationResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import javax.xml.bind.JAXBException;

public class SiteReportPrinter {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SiteReport report;
    private final ScannerDetail detail;
    private int depth;

    private final String hsClientFormat = "%-28s";
    private final String hsVersionFormat = "%-14s";
    private final String hsCiphersuiteFormat = "%-52s";
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

        appendProtocolVersions(builder);
        appendCipherSuites(builder);
        appendExtensions(builder);
        appendCompressions(builder);
        appendIntolerances(builder);
        appendAttackVulnerabilities(builder);
        appendBleichenbacherResults(builder);
        appendPaddingOracleResults(builder);
        appendDirectRaccoonResults(builder);
        //appendGcm(builder);
        appendRfc(builder);
        appendCertificate(builder);
        appendSession(builder);
        appendRenegotiation(builder);
        appendHandshakeSimulation(builder);
        appendHttps(builder);
        appendRandom(builder);
        appendPublicKeyIssues(builder);
        appendScoringResults(builder);
        appendRecommendations(builder);
        appendPerformanceData(builder);

        return builder.toString();
    }

    private StringBuilder appendHandshakeSimulation(StringBuilder builder) {
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

    private StringBuilder appendHsNormal(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation - Overview");
        prettyAppend(builder, "Tested Clients", Integer.toString(report.getSimulatedClientList().size()));
        builder.append("\n");
        String identifier;
        identifier = "Handshakes - Successful";
        if (report.getHandshakeSuccessfulCounter() == 0) {
            prettyAppend(builder, identifier, Integer.toString(report.getHandshakeSuccessfulCounter()), AnsiColor.RED);
        } else {
            prettyAppend(builder, identifier, Integer.toString(report.getHandshakeSuccessfulCounter()), AnsiColor.GREEN);
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

    private StringBuilder appendHandshakeSimulationTable(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation");
        int counter = 0;
        appendHandshakeSimulationTableRowHeading(builder, "Client", "Version", "Ciphersuite", "Forward Secrecy", "Server Public Key");
        builder.append("\n");
        for (SimulatedClientResult simulatedClient : report.getSimulatedClientList()) {
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || simulatedClient.getTlsClientConfig().isDefaultVersion()) {
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

    private StringBuilder appendHandshakeSimulationTableRowHeading(StringBuilder builder, String tlsClient, String tlsVersion,
            String ciphersuite, String forwardSecrecy, String keyLength) {
        builder.append(String.format(hsClientFormat, tlsClient));
        builder.append(String.format("| " + hsVersionFormat, tlsVersion));
        builder.append(String.format("| " + hsCiphersuiteFormat, ciphersuite));
        builder.append(String.format("| " + hsForwardSecrecyFormat, forwardSecrecy));
        builder.append(String.format("| " + hsKeyLengthFormat, keyLength));
        builder.append("\n");
        return builder;
    }

    private StringBuilder appendHandshakeTableRowSuccessful(StringBuilder builder, SimulatedClientResult simulatedClient) {
        String clientName = simulatedClient.getTlsClientConfig().getType() + ":" + simulatedClient.getTlsClientConfig().getVersion();
        builder.append(getClientColor(clientName, simulatedClient.getConnectionInsecure(), simulatedClient.getConnectionRfc7918Secure()));
        builder.append("| ").append(getProtocolVersionColor(simulatedClient.getSelectedProtocolVersion(), hsVersionFormat));
        builder.append("| ").append(getCipherSuiteColor(simulatedClient.getSelectedCiphersuite(), hsCiphersuiteFormat));
        builder.append("| ").append(getForwardSecrecyColor(simulatedClient.getForwardSecrecy()));
        builder.append("| ").append(getServerPublicKeyParameterColor(simulatedClient));
        builder.append("\n");
        return builder;
    }

    private StringBuilder appendHandshakeTableRowFailed(StringBuilder builder, SimulatedClientResult simulatedClient) {
        String clientName = simulatedClient.getTlsClientConfig().getType() + ":" + simulatedClient.getTlsClientConfig().getVersion();
        builder.append(String.format("%s", getRedString(clientName, hsClientFormat)));
        if (!simulatedClient.getFailReasons().isEmpty()) {
            for (HandshakeFailureReasons reason : simulatedClient.getFailReasons()) {
                builder.append(String.format("| %s", getRedString(reason.getReason(), hsVersionFormat)));
            }
        } else {
            ReceivingAction action = simulatedClient.getState().getWorkflowTrace().getLastReceivingAction();
            if (action.getReceivedMessages().isEmpty()) {
                builder.append(String.format("| %s", getRedString("Failed - No answer from server", "%s")));
            } else {
                StringBuilder messages = new StringBuilder();
                for (ProtocolMessage message : action.getReceivedMessages()) {
                    messages.append(message.toCompactString()).append(", ");
                }
                builder.append(String.format("| %s", getRedString("Failed - " + messages, "%s")));
            }
        }
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
            CipherSuiteGrade grade = CiphersuiteRater.getGrade(suite);
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
        CipherSuite suite = simulatedClient.getSelectedCiphersuite();
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

    private StringBuilder appendHandshakeSimulationDetails(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation - Details");
        for (SimulatedClientResult simulatedClient : report.getSimulatedClientList()) {
            prettyAppendHeading(builder, simulatedClient.getTlsClientConfig().getType() + ":" + simulatedClient.getTlsClientConfig().getVersion());
            prettyAppend(builder, "Handshake Successful", "" + simulatedClient.getHandshakeSuccessful(), simulatedClient.getHandshakeSuccessful() ? AnsiColor.GREEN : AnsiColor.RED);
            if (!simulatedClient.getHandshakeSuccessful()) {
                for (HandshakeFailureReasons failureReason : simulatedClient.getFailReasons()) {
                    prettyAppend(builder, "", getRedString(failureReason.getReason(), "%s"));
                }
            }
            builder.append("\n");
            if (simulatedClient.getConnectionInsecure() != null && simulatedClient.getConnectionInsecure()) {
                prettyAppend(builder, "Connection Insecure", simulatedClient.getConnectionInsecure(), simulatedClient.getConnectionInsecure() ? AnsiColor.RED : AnsiColor.GREEN);
                for (String reason : simulatedClient.getInsecureReasons()) {
                    prettyAppend(builder, "", reason);
                }
            }
            prettyAppend(builder, "Connection Secure (RFC 7918)", simulatedClient.getConnectionRfc7918Secure(), simulatedClient.getConnectionRfc7918Secure() ? AnsiColor.GREEN : AnsiColor.DEFAULT_COLOR);

            builder.append("\n");
            prettyAppend(builder, "Protocol Version Selected", getProtocolVersionColor(simulatedClient.getSelectedProtocolVersion(), "%s"));
            prettyAppend(builder, "Protocol Versions Client", simulatedClient.getSupportedVersionList().toString());
            prettyAppend(builder, "Protocol Versions Server", report.getVersions().toString());
            prettyAppend(builder, "Protocol Version is highest", simulatedClient.getHighestPossibleProtocolVersionSeleceted(), simulatedClient.getHighestPossibleProtocolVersionSeleceted() ? AnsiColor.GREEN : AnsiColor.RED);
            builder.append("\n");
            prettyAppend(builder, "Selected Ciphersuite", getCipherSuiteColor(simulatedClient.getSelectedCiphersuite(), "%s"));
            prettyAppend(builder, "Forward Secrecy", simulatedClient.getForwardSecrecy(), simulatedClient.getForwardSecrecy() ? AnsiColor.GREEN : AnsiColor.RED);
            builder.append("\n");
            prettyAppend(builder, "Server Public Key", getServerPublicKeyParameterColor(simulatedClient));
            builder.append("\n");
            if (simulatedClient.getSelectedCompressionMethod() != null) {
                prettyAppend(builder, "Selected Compression Method", simulatedClient.getSelectedCompressionMethod().toString());
            } else {
                String tmp = null;
                prettyAppend(builder, "Selected Compression Method", tmp);
            }
            prettyAppend(builder, "Negotiated Extensions", simulatedClient.getNegotiatedExtensions());
            prettyAppend(builder, "Alpn Protocols", simulatedClient.getAlpnAnnouncedProtocols());
        }
        return builder;
    }

    private StringBuilder appendRfc(StringBuilder builder) {
        prettyAppendHeading(builder, "RFC");
        prettyAppendCheckPattern(builder, "Checks MAC (AppData)", report.getMacCheckPatternAppData());
        prettyAppendCheckPattern(builder, "Checks MAC (Finished)", report.getMacCheckPatternFinished());
        prettyAppendCheckPattern(builder, "Checks VerifyData", report.getVerifyCheckPattern());
        return builder;
    }

    private StringBuilder appendRenegotiation(StringBuilder builder) {
        prettyAppendHeading(builder, "Renegotioation");
        prettyAppend(builder, "Clientside Secure", AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION);
        prettyAppend(builder, "Clientside Insecure", AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION);
        return builder;
    }

    private StringBuilder appendCertificate(StringBuilder builder) {
        if (report.getCertificateChain() != null) {
            CertificateChain chain = report.getCertificateChain();
            prettyAppendHeading(builder, "Certificate Chain");
            prettyAppend(builder, "Chain ordered", chain.getChainIsOrdered(), chain.getChainIsOrdered() ? AnsiColor.GREEN : AnsiColor.YELLOW);
            prettyAppend(builder, "Contains Trust Anchor", chain.getContainsTrustAnchor(), chain.getContainsTrustAnchor() ? AnsiColor.RED : AnsiColor.GREEN);
            prettyAppend(builder, "Generally Trusted", chain.getGenerallyTrusted(), chain.getGenerallyTrusted() ? AnsiColor.GREEN : AnsiColor.RED);
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
                            prettyAppend(builder, "Valid From", certReport.getValidFrom().toString() + " - NOT YET VALID", AnsiColor.RED);
                        }
                    }
                    if (certReport.getValidTo() != null) {
                        if (certReport.getValidTo().after(new Date())) {
                            prettyAppend(builder, "Valid Till", certReport.getValidTo().toString(), AnsiColor.GREEN);
                        } else {
                            prettyAppend(builder, "Valid Till", certReport.getValidTo().toString() + " - EXPIRED", AnsiColor.RED);
                        }

                    }
                    if (certReport.getValidFrom() != null && certReport.getValidTo() != null && certReport.getValidTo().after(new Date())) {
                        long time = certReport.getValidTo().getTime() - System.currentTimeMillis();
                        long days = TimeUnit.MILLISECONDS.toDays(time);
                        if (days < 1) {
                            prettyAppend(builder, "Expires in", "<1 day! This certificate expires very soon", AnsiColor.RED);
                        } else if (days < 3) {
                            prettyAppend(builder, "Expires in", days + " days! This certificate expires soon", AnsiColor.RED);
                        } else if (days < 14) {
                            prettyAppend(builder, "Expires in", days + " days. This certificate expires soon", AnsiColor.YELLOW);
                        } else if (days < 31) {
                            prettyAppend(builder, "Expires in", days + " days.", AnsiColor.DEFAULT_COLOR);
                        } else if (days < 730) {
                            prettyAppend(builder, "Expires in", days + " days.", AnsiColor.GREEN);
                        } else if (Objects.equals(certReport.getLeafCertificate(), Boolean.TRUE)) {
                            prettyAppend(builder, "Expires in", days + " days. This is usually too long for a leaf certificate", AnsiColor.RED);
                        } else {
                            prettyAppend(builder, "Expires in", days / 365 + " years", AnsiColor.GREEN);
                        }
                    }
                    if (certReport.getPublicKey() != null) {
                        prettyAppend(builder, "PublicKey", certReport.getPublicKey().toString());
                    }
                    if (certReport.getWeakDebianKey() != null) {
                        prettyAppend(builder, "Weak Debian Key", certReport.getWeakDebianKey(), certReport.getWeakDebianKey() ? AnsiColor.RED : AnsiColor.GREEN);
                    }
                    if (certReport.getSignatureAndHashAlgorithm() != null) {
                        prettyAppend(builder, "Signature Algorithm", certReport.getSignatureAndHashAlgorithm().getSignatureAlgorithm().name());
                    }
                    if (certReport.getSignatureAndHashAlgorithm() != null) {
                        if (certReport.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.SHA1 || certReport.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.MD5) {
                            if (!certReport.isTrustAnchor() && !certReport.getSelfSigned()) {
                                prettyAppend(builder, "Hash Algorithm", certReport.getSignatureAndHashAlgorithm().getHashAlgorithm().name(), AnsiColor.RED);
                            } else {
                                prettyAppend(builder, "Hash Algorithm", certReport.getSignatureAndHashAlgorithm().getHashAlgorithm().name() + " - Not critical");
                            }
                        } else {
                            prettyAppend(builder, "Hash Algorithm", certReport.getSignatureAndHashAlgorithm().getHashAlgorithm().name(), AnsiColor.GREEN);
                        }
                    }
                    if (certReport.getExtendedValidation() != null) {
                        prettyAppend(builder, "Extended Validation", certReport.getExtendedValidation(), certReport.getExtendedValidation() ? AnsiColor.GREEN : AnsiColor.DEFAULT_COLOR);
                    }
                    if (certReport.getCertificateTransparency() != null) {
                        prettyAppend(builder, "Certificate Transparency", certReport.getCertificateTransparency(), certReport.getCertificateTransparency() ? AnsiColor.GREEN : AnsiColor.YELLOW);
                    }

                    if (certReport.getCrlSupported() != null) {
                        prettyAppend(builder, "CRL Supported", certReport.getCrlSupported(), certReport.getCrlSupported() ? AnsiColor.GREEN : AnsiColor.DEFAULT_COLOR);
                    }
                    if (certReport.getOcspSupported() != null) {
                        prettyAppend(builder, "OCSP Supported", certReport.getOcspSupported(), certReport.getOcspSupported() ? AnsiColor.GREEN : AnsiColor.YELLOW);
                    }
                    if (certReport.getOcspMustStaple() != null) {
                        prettyAppend(builder, "OCSP must Staple", certReport.getOcspMustStaple());
                    }
                    if (certReport.getRevoked() != null) {
                        prettyAppend(builder, "RevocationStatus", certReport.getRevoked(), certReport.getRevoked() ? AnsiColor.RED : AnsiColor.GREEN);
                    }
                    if (certReport.getDnsCAA() != null) {
                        prettyAppend(builder, "DNS CCA", certReport.getDnsCAA(), certReport.getDnsCAA() ? AnsiColor.GREEN : AnsiColor.DEFAULT_COLOR);
                    }
                    if (certReport.getRocaVulnerable() != null) {
                        prettyAppend(builder, "ROCA (simple)", certReport.getRocaVulnerable(), certReport.getRocaVulnerable() ? AnsiColor.RED : AnsiColor.GREEN);
                    } else {
                        builder.append("ROCA (simple): not tested");
                    }
                    prettyAppend(builder, "Fingerprint (SHA256)", certReport.getSHA256Fingerprint());

                }
            }
        }
        return builder;
    }

    private StringBuilder appendSession(StringBuilder builder) {
        prettyAppendHeading(builder, "Session");
        prettyAppend(builder, "Supports Session resumption", AnalyzedProperty.SUPPORTS_SESSION_IDS);
        prettyAppend(builder, "Supports Session Tickets", AnalyzedProperty.SUPPORTS_SESSION_TICKETS);
        //prettyAppend(builder, "Session Ticket Hint", report.getSessionTicketLengthHint());
        //prettyAppendYellowOnFailure(builder, "Session Ticket Rotation", report.getSessionTicketGetsRotated());
        //prettyAppendRedOnFailure(builder, "Ticketbleed", report.getVulnerableTicketBleed());
        return builder;
    }

    private StringBuilder appendGcm(StringBuilder builder) {
        prettyAppendHeading(builder, "GCM");
        prettyAppend(builder, "GCM Nonce reuse", AnalyzedProperty.REUSES_GCM_NONCES);
        if (null == report.getGcmPattern()) {
            prettyAppend(builder, "GCM Pattern", (String) null);
        } else {
            switch (report.getGcmPattern()) {
                case AKWARD:
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

    private StringBuilder appendIntolerances(StringBuilder builder) {
        prettyAppendHeading(builder, "Common Bugs [EXPERIMENTAL]");
        prettyAppend(builder, "Version Intolerant", AnalyzedProperty.HAS_VERSION_INTOLERANCE);
        prettyAppend(builder, "Ciphersuite Intolerant", AnalyzedProperty.HAS_CIPHERSUITE_INTOLERANCE);
        prettyAppend(builder, "Extension Intolerant", AnalyzedProperty.HAS_EXTENSION_INTOLERANCE);
        prettyAppend(builder, "CS Length Intolerant (>512 Byte)", AnalyzedProperty.HAS_CIPHERSUITE_LENGTH_INTOLERANCE);
        prettyAppend(builder, "Compression Intolerant", AnalyzedProperty.HAS_COMPRESSION_INTOLERANCE);
        prettyAppend(builder, "ALPN Intolerant", AnalyzedProperty.HAS_ALPN_INTOLERANCE);
        prettyAppend(builder, "CH Length Intolerant", AnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE);
        prettyAppend(builder, "NamedGroup Intolerant", AnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE);
        prettyAppend(builder, "Empty last Extension Intolerant", AnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE);
        prettyAppend(builder, "SigHashAlgo Intolerant", AnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE);
        prettyAppend(builder, "Big ClientHello Intolerant", AnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE);
        prettyAppend(builder, "2nd Ciphersuite Byte Bug", AnalyzedProperty.HAS_SECOND_CIPHERSUITE_BYTE_BUG);
        prettyAppend(builder, "Ignores offered Ciphersuites", AnalyzedProperty.IGNORES_OFFERED_CIPHERSUITES);
        prettyAppend(builder, "Reflects offered Ciphersuites", AnalyzedProperty.REFLECTS_OFFERED_CIPHERSUITES);
        prettyAppend(builder, "Ignores offered NamedGroups", AnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS);
        prettyAppend(builder, "Ignores offered SigHashAlgos", AnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS);
        return builder;
    }

    private StringBuilder appendAttackVulnerabilities(StringBuilder builder) {
        prettyAppendHeading(builder, "Attack Vulnerabilities");
        if (report.getKnownVulnerability() == null) {
            prettyAppend(builder, "Padding Oracle", AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE);
        } else {
            prettyAppend(builder, "Padding Oracle", "true - " + report.getKnownVulnerability().getShortName(), AnsiColor.RED);
        }
        prettyAppend(builder, "Bleichenbacher", AnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER);
        prettyAppend(builder, "Direct Raccoon", AnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON);
        prettyAppend(builder, "CRIME", AnalyzedProperty.VULNERABLE_TO_CRIME);
        prettyAppend(builder, "Breach", AnalyzedProperty.VULNERABLE_TO_BREACH);
        prettyAppend(builder, "Invalid Curve", AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE);
        prettyAppend(builder, "Invalid Curve (ephemeral)", AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL);
        prettyAppend(builder, "SSL Poodle", AnalyzedProperty.VULNERABLE_TO_POODLE);
        prettyAppend(builder, "TLS Poodle", AnalyzedProperty.VULNERABLE_TO_TLS_POODLE);
        prettyAppend(builder, "Logjam", AnalyzedProperty.VULNERABLE_TO_LOGJAM);
        prettyAppend(builder, "Sweet 32", AnalyzedProperty.VULNERABLE_TO_SWEET_32);
        prettyAppend(builder, "DROWN", AnalyzedProperty.VULNERABLE_TO_DROWN);
        prettyAppend(builder, "Heartbleed", AnalyzedProperty.VULNERABLE_TO_HEARTBLEED);
        prettyAppend(builder, "EarlyCcs", AnalyzedProperty.VULNERABLE_TO_EARLY_CCS);
        return builder;
    }

    private StringBuilder appendDirectRaccoonResults(StringBuilder builder) {
        prettyAppendHeading(builder, "Direct Raccoon Responsemap");
        if (report.getDirectRaccoonResultList() == null || report.getDirectRaccoonResultList().isEmpty()) {
            prettyAppend(builder, "No Testresults");
        } else {
            for (DirectRaccoonCipherSuiteFingerprint testResult : report.getDirectRaccoonResultList()) {
                String resultString = "" + padToLength(testResult.getSuite().name(), 40) + " - " + testResult.getVersion();
                if (testResult.isHasScanningError()) {
                    prettyAppend(builder, resultString + "\t # Error during Scan", AnsiColor.YELLOW);
                } else if (Objects.equals(testResult.getVulnerable(), Boolean.TRUE)) {
                    prettyAppend(builder, resultString + "\t - " + testResult.getEqualityError() + "  VULNERABLE - Working: " + testResult.getHandshakeIsWorking(), AnsiColor.RED);
                } else if (Objects.equals(testResult.getVulnerable(), Boolean.FALSE)) {
                    prettyAppend(builder, resultString + "\t - No Behavior Difference - Working: " + testResult.getHandshakeIsWorking(), AnsiColor.GREEN);
                } else {
                    prettyAppend(builder, resultString + "\t # Unknown", AnsiColor.YELLOW);
                }

                if ((detail == ScannerDetail.DETAILED && Objects.equals(testResult.getVulnerable(), Boolean.TRUE)) || detail == ScannerDetail.ALL) {
                    if (testResult.getEqualityError() != EqualityError.NONE || detail == ScannerDetail.ALL) {
                        prettyAppend(builder, "Response Map", AnsiColor.YELLOW);
                        appendDirectRaccoonResponseMapList(builder, testResult.getResponseMapList());
                    }
                }
            }
        }
        return builder;
    }

    private StringBuilder appendDirectRaccoonResponseMapList(StringBuilder builder, List<DirectRaccoonVectorResponse> responseMapList) {
        for (int i = 0; i < responseMapList.size(); i++) {
            appendDirectRaccoonVectorResponse(builder, responseMapList.get(i));
        }
        return builder;
    }

    private StringBuilder appendDirectRaccoonVectorResponse(StringBuilder builder, DirectRaccoonVectorResponse response) {
        if (response == null || response.getFingerprint() == null) {
            prettyAppend(builder, response.getVectorName() + "\t" + padToLength("", 39) + "Missing", AnsiColor.RED);
        } else {
            if (response.isShaky()) {
                prettyAppend(builder, response.getVectorName() + "\t" + padToLength("", 39) + response.getFingerprint().toHumanReadable(), AnsiColor.YELLOW);
            } else {
                prettyAppend(builder, response.getVectorName() + "\t" + padToLength("", 39) + response.getFingerprint().toHumanReadable());
            }
        }
        return builder;
    }

    private StringBuilder appendPaddingOracleResults(StringBuilder builder) {
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
                prettyAppend(builder, "If your tested software/hardware is not in this list, please let us know so we can add it here.");
            } else {
                prettyAppend(builder, "Identification", "Could not identify vulnerability. Please contact us if you know which software/hardware is generating this behavior.", AnsiColor.YELLOW);
            }
        }
        prettyAppendHeading(builder, "PaddingOracle Responsemap");
        if (report.getPaddingOracleTestResultList() == null || report.getPaddingOracleTestResultList().isEmpty()) {
            prettyAppend(builder, "No Testresults");
        } else {
            for (PaddingOracleCipherSuiteFingerprint testResult : report.getPaddingOracleTestResultList()) {
                String resultString = "" + padToLength(testResult.getSuite().name(), 40) + " - " + testResult.getVersion();
                if (testResult.isHasScanningError()) {
                    prettyAppend(builder, resultString + "\t # Error during Scan", AnsiColor.YELLOW);
                } else if (Objects.equals(testResult.getVulnerable(), Boolean.TRUE)) {
                    prettyAppend(builder, resultString + "\t - " + testResult.getEqualityError() + "  VULNERABLE", AnsiColor.RED);
                } else if (testResult.isShakyScans()) {
                    prettyAppend(builder, resultString + "\t - Non Deterministic", AnsiColor.YELLOW);
                } else if (Objects.equals(testResult.getVulnerable(), Boolean.FALSE)) {
                    prettyAppend(builder, resultString + "\t - No Behavior Difference", AnsiColor.GREEN);
                } else {
                    prettyAppend(builder, resultString + "\t # Unknown", AnsiColor.YELLOW);
                }

                if ((detail == ScannerDetail.DETAILED && Objects.equals(testResult.getVulnerable(), Boolean.TRUE)) || detail == ScannerDetail.ALL) {
                    if (testResult.getEqualityError() != EqualityError.NONE || detail == ScannerDetail.ALL) {
                        prettyAppend(builder, "Response Map", AnsiColor.YELLOW);
                        appendPaddingOracleResponseMapList(builder, testResult.getResponseMapList());
                    }
                }
            }

        }
        if (report.getPaddingOracleShakyEvalResultList() != null && !report.getPaddingOracleShakyEvalResultList().isEmpty()) {
            prettyAppendHeading(builder, "PaddingOracle-ShakyReport");
            ShakyEvaluationReport shakyReport = report.getPaddingOracleShakyReport();
            prettyAppend(builder, "Probably Vulnerable", shakyReport.getConsideredVulnerable(), shakyReport.getConsideredVulnerable() == Boolean.TRUE ? AnsiColor.RED : AnsiColor.GREEN);
            prettyAppend(builder, "Type", "" + shakyReport.getShakyType());
            prettyAppend(builder, "Consistent", shakyReport.getConsistentAcrossCvPairs());
            prettyAppend(builder, "");
            for (ShakyVectorHolder holder : shakyReport.getVectorHolderList()) {
                double pValue = holder.computePValue();
                if (pValue > 0.05) {
                    prettyAppend(builder, "" + holder.getFingerprint().getSuite() + "/" + holder.getFingerprint().getVersion(), "Pvalue: " + String.format("%.12f", pValue), AnsiColor.GREEN);
                } else if (pValue > 0.01) {
                    prettyAppend(builder, "" + holder.getFingerprint().getSuite() + "/" + holder.getFingerprint().getVersion(), "Pvalue: " + String.format("%.12f", pValue), AnsiColor.YELLOW);
                } else {
                    prettyAppend(builder, "" + holder.getFingerprint().getSuite() + "/" + holder.getFingerprint().getVersion(), "Pvalue: " + String.format("%.12f", pValue), AnsiColor.RED);
                }
            }
        }
        return builder;
    }

    private StringBuilder appendPaddingOracleResponseMapList(StringBuilder builder, List<List<VectorResponse>> responseMapList) {
        if (responseMapList != null && !responseMapList.isEmpty()) {
            for (int vectorIndex = 0; vectorIndex < responseMapList.get(0).size(); vectorIndex++) {
                VectorResponse vectorResponse = responseMapList.get(0).get(vectorIndex);
                if (vectorResponse.isErrorDuringHandshake()) {
                    prettyAppend(builder, padToLength("\t" + vectorResponse.getPaddingVector().getName(), 40) + "ERROR", AnsiColor.RED);
                } else if (vectorResponse.isMissingEquivalent()) {
                    prettyAppend(builder, padToLength("\t" + vectorResponse.getPaddingVector().getName(), 40) + vectorResponse.getFingerprint().toHumanReadable(), AnsiColor.RED);
                } else if (vectorResponse.isShaky()) {
                    prettyAppend(builder, padToLength("\t" + vectorResponse.getPaddingVector().getName(), 40) + vectorResponse.getFingerprint().toHumanReadable(), AnsiColor.YELLOW);

                    for (int mapIndex = 1; mapIndex < responseMapList.size(); mapIndex++) {
                        VectorResponse shakyVectorResponse = responseMapList.get(mapIndex).get(vectorIndex);
                        if (shakyVectorResponse.getFingerprint() == null) {
                            prettyAppend(builder, "\t" + padToLength("", 39) + "null", AnsiColor.YELLOW);
                        } else {
                            prettyAppend(builder, "\t" + padToLength("", 39) + shakyVectorResponse.getFingerprint().toHumanReadable(), AnsiColor.YELLOW);
                        }
                    }
                } else {
                    prettyAppend(builder, padToLength("\t" + vectorResponse.getPaddingVector().getName(), 40) + vectorResponse.getFingerprint().toHumanReadable());
                    if (detail.isGreaterEqualTo(ScannerDetail.ALL)) {
                        for (int mapIndex = 1; mapIndex < responseMapList.size(); mapIndex++) {
                            VectorResponse tempVectorResponse = responseMapList.get(mapIndex).get(vectorIndex);
                            if (tempVectorResponse == null || tempVectorResponse.getFingerprint() == null) {
                                prettyAppend(builder, "\t" + padToLength("", 39) + "Missing", AnsiColor.RED);
                            } else {
                                if (tempVectorResponse.isShaky()) {
                                    prettyAppend(builder, "\t" + padToLength("", 39) + tempVectorResponse.getFingerprint().toHumanReadable(), AnsiColor.YELLOW);
                                } else {
                                    prettyAppend(builder, "\t" + padToLength("", 39) + tempVectorResponse.getFingerprint().toHumanReadable());
                                }
                            }
                        }
                    }
                }
            }
        } else {
            prettyAppend(builder, "\tNULL");
        }
        return builder;
    }

    private StringBuilder appendBleichenbacherResults(StringBuilder builder) {
        prettyAppendHeading(builder, "Bleichenbacher Details");
        if (report.getBleichenbacherTestResultList() == null || report.getBleichenbacherTestResultList().isEmpty()) {
            prettyAppend(builder, "No Testresults");
        } else {
            for (BleichenbacherTestResult testResult : report.getBleichenbacherTestResultList()) {
                String resultString = "" + padToLength(testResult.getWorkflowType().name(), 40);
                if (testResult.getVulnerable() == Boolean.TRUE) {
                    prettyAppend(builder, resultString + "\t - " + testResult.getEqualityError() + "  VULNERABLE", AnsiColor.RED);
                } else if (testResult.getVulnerable() == Boolean.FALSE) {
                    prettyAppend(builder, resultString + "\t - No Behavior Difference", AnsiColor.GREEN);
                } else {
                    prettyAppend(builder, resultString + "\t # Error during Scan", AnsiColor.YELLOW);
                }

                if (detail == ScannerDetail.DETAILED || detail == ScannerDetail.ALL) {
                    if (testResult.getEqualityError() != EqualityError.NONE || detail == ScannerDetail.ALL) {
                        prettyAppend(builder, "Response Map", AnsiColor.YELLOW);
                        if (testResult.getVectorFingerPrintPairList() != null && !testResult.getVectorFingerPrintPairList().isEmpty()) {
                            for (VectorFingerprintPair vectorFingerPrintPair : testResult.getVectorFingerPrintPairList()) {
                                prettyAppend(builder, padToLength("\t" + vectorFingerPrintPair.getVector().getDescription(), 60) + vectorFingerPrintPair.getFingerprint().toHumanReadable());
                            }
                        } else {
                            prettyAppend(builder, "\tNULL");
                        }
                    }
                }
            }
        }
        return builder;
    }

    private String toHumanReadable(ProtocolVersion version) {
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

    private StringBuilder appendCipherSuites(StringBuilder builder) {
        if (report.getCipherSuites() != null) {
            prettyAppendHeading(builder, "Supported Ciphersuites");
            for (CipherSuite suite : report.getCipherSuites()) {
                builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
            }
            if (report.getSupportedTls13CipherSuites() != null) {
                for (CipherSuite suite : report.getSupportedTls13CipherSuites()) {
                    builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
                }
            }

            for (VersionSuiteListPair versionSuitePair : report.getVersionSuitePairs()) {
                prettyAppendHeading(builder, "Supported in " + toHumanReadable(versionSuitePair.getVersion()) + (report.getResult(AnalyzedProperty.ENFOCRES_CS_ORDERING) == TestResult.TRUE ? "(server order)" : ""));
                for (CipherSuite suite : versionSuitePair.getCiphersuiteList()) {
                    builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
                }
            }
            if (report.getSupportedTls13CipherSuites() != null && report.getSupportedTls13CipherSuites().size() > 0) {
                prettyAppendHeading(builder, "Supported in TLS 1.3" + (report.getResult(AnalyzedProperty.ENFOCRES_CS_ORDERING) == TestResult.TRUE ? "(server order)" : ""));
                for (CipherSuite suite : report.getSupportedTls13CipherSuites()) {
                    builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
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
                //prettyAppend(builder, "SRP", report.getSupportsSrp());
                prettyAppend(builder, "Kerberos", AnalyzedProperty.SUPPORTS_KERBEROS);
                prettyAppend(builder, "Plain PSK", AnalyzedProperty.SUPPORTS_PSK_PLAIN);
                prettyAppend(builder, "PSK RSA", AnalyzedProperty.SUPPORTS_PSK_RSA);
                prettyAppend(builder, "PSK DHE", AnalyzedProperty.SUPPORTS_PSK_DHE);
                prettyAppend(builder, "PSK ECDHE", AnalyzedProperty.SUPPORTS_PSK_ECDHE);
                prettyAppend(builder, "Fortezza", AnalyzedProperty.SUPPORTS_FORTEZZA);
                prettyAppend(builder, "New Hope", AnalyzedProperty.SUPPORTS_NEWHOPE);
                prettyAppend(builder, "ECMQV", AnalyzedProperty.SUPPORTS_ECMQV);

                prettyAppendHeading(builder, "Cipher Types Supports");
                prettyAppend(builder, "Stream", AnalyzedProperty.SUPPORTS_STREAM_CIPHERS);
                prettyAppend(builder, "Block", AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS);
                prettyAppend(builder, "AEAD", AnalyzedProperty.SUPPORTS_AEAD);
            }
            prettyAppendHeading(builder, "Perfect Forward Secrecy");
            prettyAppend(builder, "Supports PFS", AnalyzedProperty.SUPPORTS_PFS);
            prettyAppend(builder, "Prefers PFS", AnalyzedProperty.PREFERS_PFS);
            prettyAppend(builder, "Supports Only PFS", AnalyzedProperty.SUPPORTS_ONLY_PFS);

            prettyAppendHeading(builder, "Ciphersuite General");
            prettyAppend(builder, "Enforces Ciphersuite ordering", AnalyzedProperty.ENFOCRES_CS_ORDERING);
        }
        return builder;
    }

    private StringBuilder appendProtocolVersions(StringBuilder builder) {
        if (report.getVersions() != null) {
            prettyAppendHeading(builder, "Versions");
            prettyAppend(builder, "SSL 2.0", AnalyzedProperty.SUPPORTS_SSL_2);
            prettyAppend(builder, "SSL 3.0", AnalyzedProperty.SUPPORTS_SSL_3);
            prettyAppend(builder, "TLS 1.0", AnalyzedProperty.SUPPORTS_TLS_1_0);
            prettyAppend(builder, "TLS 1.1", AnalyzedProperty.SUPPORTS_TLS_1_1);
            prettyAppend(builder, "TLS 1.2", AnalyzedProperty.SUPPORTS_TLS_1_2);
            prettyAppend(builder, "TLS 1.3", AnalyzedProperty.SUPPORTS_TLS_1_3);
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 14", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 15", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 16", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 17", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 18", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 19", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 20", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 21", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 22", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 23", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 24", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 25", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 26", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 27", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED) || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28) == TestResult.TRUE) {
                prettyAppend(builder, "TLS 1.3 Draft 28", AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28);
            }
        }
        return builder;
    }

    private StringBuilder appendHttps(StringBuilder builder) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_HTTPS) == TestResult.TRUE) {
            prettyAppendHeading(builder, "HSTS");
            if (report.getResult(AnalyzedProperty.SUPPORTS_HSTS) == TestResult.TRUE) {
                prettyAppend(builder, "HSTS", AnalyzedProperty.SUPPORTS_HSTS);
                prettyAppend(builder, "HSTS Preloading", AnalyzedProperty.SUPPORTS_HSTS_PRELOADING);
                prettyAppend(builder, "max-age (seconds)", (long) report.getHstsMaxAge());
            } else {
                prettyAppend(builder, "Not supported");
            }
            prettyAppendHeading(builder, "HPKP");
            if (report.getResult(AnalyzedProperty.SUPPORTS_HPKP) == TestResult.TRUE || report.getResult(AnalyzedProperty.SUPPORTS_HPKP_REPORTING) == TestResult.TRUE) {
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
        }
        return builder;
    }

    private StringBuilder appendExtensions(StringBuilder builder) {
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

    private void appendRandom(StringBuilder builder) {
        prettyAppendHeading(builder, "Nonce");
        prettyAppendRandom(builder, "Random", report.getRandomEvaluationResult());
    }

    private void appendPublicKeyIssues(StringBuilder builder) {
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

    private void appendScoringResults(StringBuilder builder) {
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
                int scoreInluence = 0;
                StringBuilder additionalInfo = new StringBuilder();
                if (influencer.getReferencedProperty() != null) {
                    additionalInfo.append(" (Score: 0). -> See ").append(influencer.getReferencedProperty())
                            .append(" for more information");
                } else {
                    scoreInluence = influencer.getInfluence();
                    additionalInfo.append(" (Score: ").append((scoreInluence > 0 ? "+" : "")).append(scoreInluence);
                    if (influencer.hasScoreCap()) {
                        additionalInfo.append(", Score cap: ").append(influencer.getScoreCap());
                    }
                    additionalInfo.append(")");
                }
                String result = recommendation.getShortName() + ": " + influencer.getResult() + additionalInfo;
                if (scoreInluence > 0) {
                    prettyAppend(builder, result, AnsiColor.GREEN);
                } else if (scoreInluence < -50) {
                    prettyAppend(builder, result, AnsiColor.RED);
                } else if (scoreInluence < 0) {
                    prettyAppend(builder, result, AnsiColor.YELLOW);
                }
            });
        } catch (JAXBException ex) {
            prettyAppend(builder, "Could not append scoring results", AnsiColor.RED);
            prettyAppend(builder, ex.getLocalizedMessage(), AnsiColor.RED);
        }
    }

    private void appendRecommendations(StringBuilder builder) {
        prettyAppendHeading(builder, "Recommedations");

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
                    PropertyResultRecommendation resultRecommendation = recommendation.getPropertyResultRecommendation(influencer.getResult());
                    if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                        printFullRecommendation(builder, rater, recommendation, influencer, resultRecommendation);
                    } else {
                        printShortRecommendation(builder, influencer, resultRecommendation);
                    }
                }
            });
        } catch (Exception ex) {
            prettyAppend(builder, "Could not append recommendations - unreleated error", AnsiColor.RED);
            LOGGER.error("Could not append recommendations", ex);
        }
    }

    private void printFullRecommendation(StringBuilder builder, SiteReportRater rater, Recommendation recommendation,
            PropertyResultRatingInfluencer influencer, PropertyResultRecommendation resultRecommendation) {
        AnsiColor color = getRecommendationColor(influencer);
        prettyAppend(builder, "", color);
        prettyAppend(builder, recommendation.getShortName() + ": " + influencer.getResult(), color);
        int scoreInluence = 0;
        String additionalInfo = "";
        if (influencer.getReferencedProperty() != null) {
            scoreInluence = rater.getRatingInfluencers().getPropertyRatingInfluencer(influencer.getReferencedProperty(),
                    influencer.getReferencedPropertyResult()).getInfluence();
            Recommendation r = rater.getRecommendations().getRecommendation(influencer.getReferencedProperty());
            additionalInfo = " -> This score comes from \"" + r.getShortName() + "\"";
        } else {
            scoreInluence = influencer.getInfluence();
        }
        prettyAppend(builder, "  Score: " + scoreInluence + additionalInfo, color);
        if (influencer.hasScoreCap()) {
            prettyAppend(builder, "  Score cap: " + influencer.getScoreCap(), color);
        }
        prettyAppend(builder, "  Information: " + resultRecommendation.getShortDescription(), color);
        prettyAppend(builder, "  Recommendation: " + resultRecommendation.getHandlingRecommendation(), color);
    }

    private void printShortRecommendation(StringBuilder builder, PropertyResultRatingInfluencer influencer,
            PropertyResultRecommendation resultRecommendation) {
        AnsiColor color = getRecommendationColor(influencer);
        prettyAppend(builder, resultRecommendation.getShortDescription() + ". " + resultRecommendation.getHandlingRecommendation(), color);
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
        CipherSuiteGrade grade = CiphersuiteRater.getGrade(suite);
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

    private StringBuilder appendCurves(StringBuilder builder) {
        if (report.getSupportedNamedGroups() != null) {
            prettyAppendHeading(builder, "Supported Named Groups");
            if (report.getSupportedNamedGroups().size() > 0) {
                for (NamedGroup group : report.getSupportedNamedGroups()) {
                    builder.append(group.name()).append("\n");
                }
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    private StringBuilder appendSignatureAndHashAlgorithms(StringBuilder builder) {
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

    private StringBuilder appendCompressions(StringBuilder builder) {
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
        return (printColorful ? AnsiColor.GREEN.getCode() : AnsiColor.RESET.getCode()) + String.format(format, value == null ? "Unknown" : value) + AnsiColor.RESET.getCode();
    }

    private String getYellowString(String value, String format) {
        return (printColorful ? AnsiColor.YELLOW.getCode() : AnsiColor.RESET.getCode()) + String.format(format, value == null ? "Unknown" : value) + AnsiColor.RESET.getCode();
    }

    private String getRedString(String value, String format) {
        return (printColorful ? AnsiColor.RED.getCode() : AnsiColor.RESET.getCode()) + String.format(format, value == null ? "Unknown" : value) + AnsiColor.RESET.getCode();
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
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : value).append("\n");
    }

    private StringBuilder prettyAppend(StringBuilder builder, String name, Long value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : value).append("\n");
    }

    private StringBuilder prettyAppend(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : value).append("\n");
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

        return builder.append(printColorful ? AnsiColor.BOLD.getCode() + AnsiColor.BLUE.getCode() : AnsiColor.RESET.getCode()).append("\n------------------------------------------------------------\n").append(value).append("\n\n").append(AnsiColor.RESET.getCode());
    }

    private StringBuilder prettyAppendUnderlined(StringBuilder builder, String name, String value) {
        return builder.append(addIndentations(name)).append(": ").append((printColorful ? AnsiColor.UNDERLINE.getCode() + value + AnsiColor.RESET.getCode() : value)).append("\n");
    }

    private StringBuilder prettyAppendUnderlined(StringBuilder builder, String name, boolean value) {
        return builder.append(addIndentations(name)).append(": ").append((printColorful ? AnsiColor.UNDERLINE.getCode() + value + AnsiColor.RESET.getCode() : value)).append("\n");
    }

    private StringBuilder prettyAppendUnderlined(StringBuilder builder, String name, long value) {
        return builder.append(addIndentations(name)).append(": ").append((printColorful == false ? AnsiColor.UNDERLINE.getCode() + value + AnsiColor.RESET.getCode() : value)).append("\n");
    }

    private StringBuilder prettyAppendSubheading(StringBuilder builder, String name) {
        depth = 1;
        return builder.append("--|").append(printColorful ? AnsiColor.BOLD.getCode() + AnsiColor.PURPLE.getCode() + AnsiColor.UNDERLINE.getCode() + name + "\n\n" + AnsiColor.RESET.getCode() : name + "\n\n");
    }

    private StringBuilder prettyAppendSubSubheading(StringBuilder builder, String name) {
        depth = 2;
        return builder.append("----|").append(printColorful ? AnsiColor.BOLD.getCode() + AnsiColor.PURPLE.getCode() + AnsiColor.UNDERLINE.getCode() + name + "\n\n" + AnsiColor.RESET.getCode() : name + "\n\n");
    }

    private StringBuilder prettyAppendSubSubSubheading(StringBuilder builder, String name) {
        depth = 3;
        return builder.append("------|").append(printColorful ? AnsiColor.BOLD.getCode() + AnsiColor.PURPLE.getCode() + AnsiColor.UNDERLINE.getCode() + name + "\n\n" + AnsiColor.RESET.getCode() : name + "\n\n");
    }

    private void prettyAppendDrown(StringBuilder builder, String testName, DrownVulnerabilityType drownVulnerable) {
        builder.append(addIndentations(testName)).append(": ");
        if (drownVulnerable == null) {
            prettyAppend(builder, "Unknown");
            return;
        }
        switch (drownVulnerable) {
            case FULL:
                prettyAppend(builder, "true - fully exploitable", AnsiColor.RED);
                break;
            case SSL2:
                prettyAppend(builder, "true - SSL 2 supported!", AnsiColor.RED);
                break;
            case NONE:
                prettyAppend(builder, "false", AnsiColor.GREEN);
                break;
            case UNKNOWN:
                prettyAppend(builder, "Unknown");
                break;
        }
    }

    private void prettyAppendEarlyCcs(StringBuilder builder, String testName, EarlyCcsVulnerabilityType earlyCcsVulnerable) {
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
                throw new IllegalArgumentException("Unkown MacCheckPattern Type: " + pattern.getType());
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

    private StringBuilder appendTls13Groups(StringBuilder builder) {
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

    private void prettyAppendRandom(StringBuilder builder, String testName, RandomEvaluationResult randomEvaluationResult) {
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
        }
    }

    public void setDepth(int depth) {
        this.depth = depth;
    }

    private void appendPerformanceData(StringBuilder builder) {
        if (detail.isGreaterEqualTo(ScannerDetail.ALL)) {
            prettyAppendHeading(builder, "Scanner Performance");
            prettyAppend(builder, "TCP connections", "" + report.getPerformedTcpConnections());
            prettyAppendSubheading(builder, "Probe execution performance");
            for (PerformanceData data : report.getPerformanceList()) {
                prettyAppendSubheading(builder, data.getType().name());
                prettyAppend(builder, "Started: " + data.getStarttime());
                prettyAppend(builder, "Finished: " + data.getStoptime());
                prettyAppend(builder, "Total:" + (data.getStoptime() - data.getStarttime()) + " ms");
                prettyAppend(builder, "");
            }
        } else {
            LOGGER.debug("Not printing performance data.");
        }
    }
}
