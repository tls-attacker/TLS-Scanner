/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.GuidelineReport;
import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.scanner.core.report.PerformanceData;
import de.rub.nds.scanner.core.report.PrintingScheme;
import de.rub.nds.scanner.core.report.ReportPrinter;
import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.scanner.core.report.rating.PropertyResultRecommendation;
import de.rub.nds.scanner.core.report.rating.Recommendation;
import de.rub.nds.scanner.core.report.rating.Recommendations;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.scanner.core.report.rating.SiteReportRater;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.AlpnProtocol;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameterEntry;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.RandomType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateIssue;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.core.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.core.probe.padding.PaddingOracleStrength;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.report.CipherSuiteGrade;
import de.rub.nds.tlsscanner.core.report.CipherSuiteRater;
import de.rub.nds.tlsscanner.core.report.EntropyReport;
import de.rub.nds.tlsscanner.core.vector.response.EqualityError;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.core.vector.statistics.ResponseCounter;
import de.rub.nds.tlsscanner.core.vector.statistics.VectorContainer;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.prime.CommonDhValues;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.ConnectionInsecure;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.HandshakeFailureReasons;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.InvalidCurveResponse;
import de.rub.nds.tlsscanner.serverscanner.probe.namedgroup.NamedGroupWitness;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentSummarizableResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentTestResults;
import de.rub.nds.tlsscanner.serverscanner.probe.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.serverscanner.probe.result.raccoonattack.RaccoonAttackProbabilities;
import de.rub.nds.tlsscanner.serverscanner.probe.result.raccoonattack.RaccoonAttackPskProbabilities;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.FoundDefaultHmacKey;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.FoundDefaultStek;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.FoundSecret;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.SessionTicketAfterStats;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.TicketManipulationResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.TicketPaddingOracleOffsetResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.TicketPaddingOracleResult;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPaddingOracleVectorSecond;
import de.rub.nds.tlsscanner.serverscanner.report.rating.DefaultRatingLoader;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.Days;
import org.joda.time.Period;
import org.joda.time.format.PeriodFormat;

public class ServerReportPrinter extends ReportPrinter<ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String hsClientFormat = "%-28s";
    private final String hsVersionFormat = "%-14s";
    private final String hsCipherSuiteFormat = "%-52s";
    private final String hsForwardSecrecyFormat = "%-19s";
    private final String hsKeyLengthFormat = "%-17s";

    public ServerReportPrinter(
            ServerReport report,
            ScannerDetail detail,
            PrintingScheme scheme,
            boolean printColorful) {
        super(detail, scheme, printColorful, report);
    }

    @Override
    public String getFullReport() {
        StringBuilder builder = new StringBuilder();
        builder.append("Report for ");
        builder.append(report.getHost() + ":" + report.getPort());
        builder.append("\n");
        if (Objects.equals(report.getServerIsAlive(), Boolean.FALSE)) {
            builder.append("Cannot reach the Server. Is it online?");
            return builder.toString();
        }
        if (Objects.equals(report.getSpeaksProtocol(), Boolean.FALSE)) {
            builder.append(
                    "Server does not seem to support "
                            + report.getProtocolType().getName()
                            + " on the scanned port");
            return builder.toString();
        }
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
        appendDirectRaccoonResults(builder);
        appendInvalidCurveResults(builder);
        appendRaccoonAttackDetails(builder);
        appendCertificates(builder);
        appendSession(builder);
        appendSessionTicketEval(builder);
        appendRenegotiation(builder);
        appendHttps(builder);
        appendRandomness(builder);
        appendPublicKeyIssues(builder);
        if (report.getProtocolType() == ProtocolType.QUIC) {
            appendQuicSpecificResults(builder);
        }
        if (report.getProtocolType() == ProtocolType.DTLS) {
            appendDtlsSpecificResults(builder);
        }
        appendScoringResults(builder);
        appendRecommendations(builder);
        if (report.getProtocolType() != ProtocolType.DTLS) {
            appendGuidelines(builder);
        }
        appendPerformanceData(builder);
        appendMissingProbesRequirements(builder);

        return builder.toString();
    }

    private void appendMissingProbesRequirements(StringBuilder builder) {
        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            prettyAppendHeading(
                    builder, "Unexecuted Probes and the respectively missing Requirements");
            for (ScannerProbe<?, ?> unexecutedProbe : report.getUnexecutedProbes())
                // noinspection unchecked
                prettyAppend(
                        builder,
                        unexecutedProbe.getProbeName(),
                        ((ScannerProbe<ServerReport, ?>) unexecutedProbe)
                                .getRequirements().getUnfulfilledRequirements(report).stream()
                                        .map(Object::toString)
                                        .collect(Collectors.joining(";")));
        }
    }

    private void appendDtlsSpecificResults(StringBuilder builder) {
        prettyAppendHeading(builder, "DTLS Features");
        prettyAppend(builder, "Server changes port", TlsAnalyzedProperty.CHANGES_PORT);
        if (report.getResult(TlsAnalyzedProperty.CHANGES_PORT) == TestResults.TRUE) {
            prettyAppend(
                    builder, "-To random ports", TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS);
        }
        prettyAppend(builder, "Supports reordering", TlsAnalyzedProperty.SUPPORTS_REORDERING);

        prettyAppendHeading(builder, "DTLS Fragmentation");
        prettyAppend(
                builder, "Supports fragmentation", TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION);
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION)
                == TestResults.PARTIALLY) {
            if (report.getResult(TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION)
                    == TestResults.TRUE) {
                prettyAppend(builder, "-Requires Max Fragment Length extension");
            } else {
                prettyAppend(builder, "-After cookie exchange");
            }
        }
        prettyAppend(
                builder,
                "Supports fragmentation with individual transport packets",
                TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS);
        if (report.getResult(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS)
                == TestResults.PARTIALLY) {
            if (report.getResult(
                            TlsAnalyzedProperty
                                    .DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION)
                    == TestResults.TRUE) {
                prettyAppend(builder, "-Requires Max Fragment Length extension");
            } else {
                prettyAppend(builder, "-After cookie exchange");
            }
        }

        prettyAppendHeading(builder, "DTLS Hello Verify Request");
        prettyAppend(builder, "HVR Retransmissions", TlsAnalyzedProperty.HAS_HVR_RETRANSMISSIONS);
        if (report.getCookieLength() != null) {
            prettyAppend(builder, "Cookie length", "" + report.getCookieLength());
        } else {
            prettyAppend(builder, "Cookie length", TlsAnalyzedProperty.HAS_COOKIE_CHECKS);
        }
        prettyAppend(builder, "Checks cookie", TlsAnalyzedProperty.HAS_COOKIE_CHECKS);
        prettyAppend(builder, "Cookie is influenced by");
        prettyAppend(builder, "-ip", TlsAnalyzedProperty.USES_IP_ADDRESS_FOR_COOKIE);
        prettyAppend(builder, "-port", TlsAnalyzedProperty.USES_PORT_FOR_COOKIE);
        prettyAppend(builder, "-version", TlsAnalyzedProperty.USES_VERSION_FOR_COOKIE);
        prettyAppend(builder, "-random", TlsAnalyzedProperty.USES_RANDOM_FOR_COOKIE);
        prettyAppend(builder, "-session id", TlsAnalyzedProperty.USES_SESSION_ID_FOR_COOKIE);
        prettyAppend(builder, "-cipher suites", TlsAnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE);
        prettyAppend(builder, "-compressions", TlsAnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE);

        prettyAppendHeading(builder, "DTLS Message Sequence Number");
        prettyAppend(
                builder,
                "Accepts start with invalid msg seq",
                TlsAnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE);
        prettyAppend(
                builder,
                "Misses msg seq checks",
                TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS);
        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            prettyAppend(
                    builder,
                    "-Accepts: 0,4,5,6",
                    TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE);
            prettyAppend(
                    builder,
                    "-Accepts: 0,4,8,9",
                    TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE);
            prettyAppend(
                    builder,
                    "-Accepts: 0,8,4,5",
                    TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES);
        }

        prettyAppendHeading(builder, "DTLS Retransmissions");
        prettyAppend(builder, "Sends retransmissions", TlsAnalyzedProperty.SENDS_RETRANSMISSIONS);
        prettyAppend(
                builder,
                "Processes retransmissions",
                TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS);
        prettyAppend(
                builder,
                "Total retransmissions received",
                "" + report.getTotalReceivedRetransmissions());
        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                && report.getRetransmissionCounters() != null) {
            for (HandshakeMessageType type : report.getRetransmissionCounters().keySet()) {
                prettyAppend(
                        builder,
                        "-" + type.getName(),
                        "" + report.getRetransmissionCounters().get(type));
            }
        }

        prettyAppendHeading(builder, "DTLS Bugs");
        prettyAppend(
                builder,
                "Accepts Finished with Epoch 0",
                TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_FINISHED);
        prettyAppend(
                builder,
                "Accepts App Data with Epoch 0",
                TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_APP_DATA);
        prettyAppend(builder, "Early Finished", TlsAnalyzedProperty.HAS_EARLY_FINISHED_BUG);

        List<ApplicationProtocol> applications = report.getSupportedApplicationProtocols();
        if (applications != null) {
            prettyAppendHeading(builder, "Supported Applications");
            for (ApplicationProtocol application : applications) {
                builder.append(application).append("\n");
            }
        }
    }

    private void appendQuicSpecificResults(StringBuilder builder) {
        appendQuicSupportedVersionsResults(builder);
        appendQuicTransportParametersResults(builder);
        appendQuicAfterHandshakeResults(builder);
        appendQuicRetryPacketResults(builder);
        appendQuicAntiDosLimitResults(builder);
        appendQuicFragmentationResults(builder);
        appendQuicConnectionMigrationResults(builder);
        appendQuicTls12HandshakeResults(builder);
    }

    private void appendQuicFragmentationResults(StringBuilder builder) {
        prettyAppendHeading(builder, "QUIC Fragmentation Probe Results");
        prettyAppend(
                builder,
                "Server accepts splitted Client Hello messages ",
                QuicAnalyzedProperty.PROCESSES_SPLITTED_CLIENT_HELLO);
    }

    private void appendQuicAntiDosLimitResults(StringBuilder builder) {
        prettyAppendHeading(builder, "QUIC Anti Dos Limit Probe Results");
        TestResult holdsAntiDosLimit = report.getResult(QuicAnalyzedProperty.HOLDS_ANTI_DOS_LIMIT);
        if (holdsAntiDosLimit == TestResults.TRUE) {
            prettyAppend(builder, "Server holds anti DoS limit", true, AnsiColor.GREEN);
        } else if (holdsAntiDosLimit == TestResults.FALSE) {
            prettyAppend(builder, "Server holds anti DoS limit", false, AnsiColor.YELLOW);
        } else {
            prettyAppend(builder, "testing failed", AnsiColor.RED);
        }
    }

    private void appendQuicAfterHandshakeResults(StringBuilder builder) {
        prettyAppendHeading(builder, "QUIC After Handshake Probe Results");
        prettyAppend(builder, "QUIC NEW_TOKEN Frame");
        TestResult isNewTokenFrameSend =
                report.getResult(QuicAnalyzedProperty.IS_NEW_TOKEN_FRAME_SEND);
        if (isNewTokenFrameSend == TestResults.TRUE) {
            prettyAppend(builder, "Server sends frame", true);
            prettyAppend(
                    builder,
                    "Number of Tokens",
                    ""
                            + report.getIntegerResult(
                                            QuicAnalyzedProperty.NUMBER_OF_NEW_TOKEN_FRAMES)
                                    .getValue());
            prettyAppend(
                    builder,
                    "Token Length",
                    "" + report.getLongResult(QuicAnalyzedProperty.NEW_TOKEN_LENGTH).getValue());
        } else if (isNewTokenFrameSend == TestResults.FALSE) {
            prettyAppend(builder, "Server sends NEW_TOKEN frame", false);
        } else {
            prettyAppend(builder, "testing failed", AnsiColor.RED);
        }
        prettyAppend(builder, "\nQUIC NEW_CONNECTION_ID Frame");
        TestResult isNewConnectionIdFramesSend =
                report.getResult(QuicAnalyzedProperty.IS_NEW_CONNECTION_ID_FRAME_SEND);
        if (isNewConnectionIdFramesSend == TestResults.TRUE) {
            prettyAppend(builder, "Server sends frame", true);
            prettyAppend(
                    builder,
                    "Number of Conenction IDs",
                    ""
                            + report.getIntegerResult(
                                            QuicAnalyzedProperty.NUMBER_OF_NEW_CONNECTION_ID_FRAMES)
                                    .getValue());
        } else if (isNewConnectionIdFramesSend == TestResults.FALSE) {
            prettyAppend(builder, "Server sends NEW_CONNECTION_ID frame", false);
        } else {
            prettyAppend(builder, "testing failed", AnsiColor.RED);
        }
    }

    private void appendQuicRetryPacketResults(StringBuilder builder) {
        prettyAppendHeading(builder, "QUIC Retry Packet Probe Results");
        if (report.getResult(QuicAnalyzedProperty.RETRY_REQUIRED) == TestResults.TRUE) {
            prettyAppend(builder, "Server sends RETRY packet", true, AnsiColor.GREEN);
            prettyAppend(
                    builder,
                    "Token Length",
                    report.getIntegerResult(QuicAnalyzedProperty.RETRY_TOKEN_LENGTH)
                            .getValue()
                            .toString());
            prettyAppend(
                    builder,
                    "Server checks received token",
                    QuicAnalyzedProperty.HAS_RETRY_TOKEN_CHECKS);
            prettyAppend(
                    builder,
                    "Token Retransmissions",
                    QuicAnalyzedProperty.HAS_RETRY_TOKEN_RETRANSMISSIONS);
        } else {
            prettyAppend(builder, "Server sends RETRY packet", false, AnsiColor.YELLOW);
        }
    }

    private void appendQuicConnectionMigrationResults(StringBuilder builder) {
        prettyAppendHeading(builder, "QUIC Connection Migration Probe Results");
        prettyAppend(
                builder,
                "Port Connection Migration Successful",
                QuicAnalyzedProperty.PORT_CONNECTION_MIGRATION_SUCCESSFUL);
        prettyAppend(builder, "IPV6 Address", report.getIpv6Address());
        prettyAppend(
                builder, "IPV6 Handshake Successful", QuicAnalyzedProperty.IPV6_HANDSHAKE_DONE);
        prettyAppend(
                builder,
                "IPV4 To IPV6 Connection Migration Successful",
                QuicAnalyzedProperty.IPV6_CONNECTION_MIGRATION_SUCCESSFUL);
    }

    private void appendQuicTls12HandshakeResults(StringBuilder builder) {
        prettyAppendHeading(builder, "QUIC TLS 1.2 Handshake Probe Results");
        TestResult tls12HandshakeDone = report.getResult(QuicAnalyzedProperty.TLS12_HANDSHAKE_DONE);
        if (tls12HandshakeDone == TestResults.TRUE) {
            prettyAppend(builder, "Handshake Successful", true, AnsiColor.RED);
        } else if (tls12HandshakeDone == TestResults.FALSE) {
            prettyAppend(builder, "Handshake Successful", false, AnsiColor.GREEN);
            if (report.getQuicTls12HandshakeConnectionCloseFrame() != null) {
                prettyAppend(builder, "Server closed connection with:");
                prettyAppend(
                        builder, report.getQuicTls12HandshakeConnectionCloseFrame().toString());
            }
        } else {
            prettyAppend(builder, "testing failed", AnsiColor.RED);
        }
    }

    private void appendQuicTransportParametersResults(StringBuilder builder) {
        prettyAppendHeading(builder, "QUIC Transport Parameters");
        TestResult sendsTransportParameters =
                report.getResult(QuicAnalyzedProperty.SENDS_TRANSPORT_PARAMETERS);
        if (sendsTransportParameters == TestResults.TRUE) {
            prettyAppend(builder, "Server sends extension", true, AnsiColor.GREEN);
            prettyAppend(builder, "Extension contains:");
            for (QuicTransportParameterEntry quicTransportParameter :
                    report.getQuicTransportParameters().toListOfEntries()) {
                prettyAppend(
                        builder,
                        " " + quicTransportParameter.getEntryType().name(),
                        quicTransportParameter.entryValueToString());
            }
        } else if (sendsTransportParameters == TestResults.FALSE) {
            prettyAppend(builder, "Server sends extension", false, AnsiColor.YELLOW);
        } else {
            prettyAppend(builder, "testing failed", AnsiColor.RED);
        }
    }

    private void appendQuicSupportedVersionsResults(StringBuilder builder) {
        prettyAppendHeading(builder, "QUIC Supported Versions");
        TestResult sendsTransportParameters =
                report.getResult(QuicAnalyzedProperty.SENDS_VERSIONS_NEGOTIATION_PACKET);
        if (sendsTransportParameters == TestResults.TRUE) {
            prettyAppend(builder, "Server sends VN Packet", true, AnsiColor.GREEN);
            prettyAppend(builder, "Supported Versions:");
            for (byte[] version : report.getSupportedQuicVersions()) {
                prettyAppend(
                        builder,
                        " "
                                + QuicVersion.getFromVersionBytes(version)
                                + "("
                                + ArrayConverter.bytesToHexString(version)
                                + ")");
            }
        } else if (sendsTransportParameters == TestResults.FALSE) {
            prettyAppend(builder, "Server sends VN Packet", false, AnsiColor.YELLOW);
        } else {
            prettyAppend(builder, "testing failed", AnsiColor.RED);
        }
    }

    private void appendDirectRaccoonResults(StringBuilder builder) {
        if (report.getRaccoonTestResultList() != null) {
            List<InformationLeakTest<?>> raccoonResults = new LinkedList<>();
            raccoonResults.addAll(report.getRaccoonTestResultList());
            appendInformationLeakTestList(builder, raccoonResults, "Direct Raccoon Results");
        }
    }

    public StringBuilder appendHsNormal(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation - Overview");
        prettyAppend(
                builder,
                "Tested Clients",
                Integer.toString(report.getSimulatedClientsResultList().size()));
        builder.append("\n");
        String identifier;
        identifier = "Handshakes - Successful";
        if (report.getHandshakeSuccessfulCounter() == 0) {
            prettyAppend(
                    builder,
                    identifier,
                    Integer.toString(report.getHandshakeSuccessfulCounter()),
                    AnsiColor.RED);
        } else {
            prettyAppend(
                    builder,
                    identifier,
                    Integer.toString(report.getHandshakeSuccessfulCounter()),
                    AnsiColor.GREEN);
        }
        identifier = "Handshakes - Failed";
        if (report.getHandshakeFailedCounter() == 0) {
            prettyAppend(
                    builder,
                    identifier,
                    Integer.toString(report.getHandshakeFailedCounter()),
                    AnsiColor.GREEN);
        } else {
            prettyAppend(
                    builder,
                    identifier,
                    Integer.toString(report.getHandshakeFailedCounter()),
                    AnsiColor.RED);
        }
        builder.append("\n");
        return builder;
    }

    public StringBuilder appendHandshakeSimulationTableRowHeading(
            StringBuilder builder,
            String tlsClient,
            String tlsVersion,
            String cipherSuite,
            String forwardSecrecy,
            String keyLength) {
        builder.append(String.format(hsClientFormat, tlsClient));
        builder.append(String.format("| " + hsVersionFormat, tlsVersion));
        builder.append(String.format("| " + hsCipherSuiteFormat, cipherSuite));
        builder.append(String.format("| " + hsForwardSecrecyFormat, forwardSecrecy));
        builder.append(String.format("| " + hsKeyLengthFormat, keyLength));
        builder.append("\n");
        return builder;
    }

    public StringBuilder appendHandshakeTableRowSuccessful(
            StringBuilder builder, SimulatedClientResult simulatedClient) {
        String clientName =
                simulatedClient.getTlsClientConfig().getType()
                        + ":"
                        + simulatedClient.getTlsClientConfig().getVersion();
        builder.append(
                getClientColor(
                        clientName,
                        simulatedClient.getConnectionInsecure(),
                        simulatedClient.getConnectionRfc7918Secure()));
        builder.append("| ")
                .append(
                        getProtocolVersionColor(
                                simulatedClient.getSelectedProtocolVersion(), hsVersionFormat));
        builder.append("| ")
                .append(
                        getCipherSuiteColor(
                                simulatedClient.getSelectedCipherSuite(), hsCipherSuiteFormat));
        builder.append("| ").append(getForwardSecrecyColor(simulatedClient.getForwardSecrecy()));
        builder.append("| ").append(getServerPublicKeyParameterColor(simulatedClient));
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
        for (SimulatedClientResult simulatedClient : report.getSimulatedClientsResultList()) {
            prettyAppendHeading(
                    builder,
                    simulatedClient.getTlsClientConfig().getType()
                            + ":"
                            + simulatedClient.getTlsClientConfig().getVersion());

            prettyAppend(
                    builder,
                    "Handshake Successful",
                    "" + simulatedClient.getHandshakeSuccessful(),
                    simulatedClient.getHandshakeSuccessful() ? AnsiColor.GREEN : AnsiColor.RED);
            if (!simulatedClient.getHandshakeSuccessful()) {
                for (HandshakeFailureReasons failureReason : simulatedClient.getFailReasons()) {
                    prettyAppend(builder, "", getRedString(failureReason.getReason(), "%s"));
                }
            }
            builder.append("\n");
            if (simulatedClient.getConnectionInsecure() != null
                    && simulatedClient.getConnectionInsecure()) {
                prettyAppend(
                        builder,
                        "Connection Insecure",
                        simulatedClient.getConnectionInsecure(),
                        simulatedClient.getConnectionInsecure() ? AnsiColor.RED : AnsiColor.GREEN);
                for (String reason : simulatedClient.getInsecureReasons()) {
                    prettyAppend(builder, "", reason);
                }
            }
            prettyAppend(
                    builder,
                    "Connection Secure (RFC 7918)",
                    simulatedClient.getConnectionRfc7918Secure(),
                    simulatedClient.getConnectionRfc7918Secure()
                            ? AnsiColor.GREEN
                            : AnsiColor.DEFAULT_COLOR);

            builder.append("\n");
            prettyAppend(
                    builder,
                    "Protocol Version Selected",
                    getProtocolVersionColor(simulatedClient.getSelectedProtocolVersion(), "%s"));
            prettyAppend(
                    builder,
                    "Protocol Versions Client",
                    simulatedClient.getSupportedVersionList().toString());
            prettyAppend(
                    builder,
                    "Protocol Versions Server",
                    report.getSupportedProtocolVersions().toString());
            prettyAppend(
                    builder,
                    "Protocol Version is highest",
                    simulatedClient.getHighestPossibleProtocolVersionSelected(),
                    simulatedClient.getHighestPossibleProtocolVersionSelected()
                            ? AnsiColor.GREEN
                            : AnsiColor.RED);
            builder.append("\n");
            prettyAppend(
                    builder,
                    "Selected CipherSuite",
                    getCipherSuiteColor(simulatedClient.getSelectedCipherSuite(), "%s"));
            prettyAppend(
                    builder,
                    "Forward Secrecy",
                    simulatedClient.getForwardSecrecy(),
                    simulatedClient.getForwardSecrecy() ? AnsiColor.GREEN : AnsiColor.RED);
            builder.append("\n");
            prettyAppend(
                    builder,
                    "Server Public Key",
                    getServerPublicKeyParameterColor(simulatedClient));
            builder.append("\n");
            if (simulatedClient.getSelectedCompressionMethod() != null) {
                prettyAppend(
                        builder,
                        "Selected Compression Method",
                        simulatedClient.getSelectedCompressionMethod().toString());
            } else {
                String tmp = null;
                prettyAppend(builder, "Selected Compression Method", tmp);
            }
            prettyAppend(
                    builder, "Negotiated Extensions", simulatedClient.getNegotiatedExtensions());
            // prettyAppend(builder, "Alpn Protocols",
            // simulatedClient.getAlpnAnnouncedProtocols());
        }
        return builder;
    }

    public StringBuilder appendRfc(StringBuilder builder) {
        prettyAppendHeading(builder, "RFC (Experimental)");
        prettyAppend(
                builder,
                "Checks MAC (AppData)",
                report.getMacCheckPatternAppData().getType().name());
        prettyAppend(
                builder,
                "Checks MAC (Finished)",
                report.getMacCheckPatternFinished().getType().name());
        prettyAppend(builder, "Checks VerifyData", report.getVerifyCheckPattern().getType().name());
        return builder;
    }

    public StringBuilder appendRenegotiation(StringBuilder builder) {
        prettyAppendHeading(builder, "Renegotioation");
        prettyAppend(
                builder,
                "Secure (Extension)",
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION);
        prettyAppend(
                builder,
                "Secure (CipherSuite)",
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE);
        prettyAppend(
                builder,
                "Insecure",
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION);
        if (report.getProtocolType() == ProtocolType.DTLS) {
            prettyAppend(
                    builder,
                    "DTLS cookie exchange in renegotiation",
                    TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_RENEGOTIATION);
        }
        return builder;
    }

    public StringBuilder appendCertificates(StringBuilder builder) {
        int certCtr = 1;
        if (report.getCertificateChainList() != null
                && !report.getCertificateChainList().isEmpty()) {
            for (CertificateChainReport chainReport : report.getCertificateChainList()) {
                prettyAppendHeading(
                        builder,
                        "Certificate Chain (Certificate "
                                + certCtr
                                + " of "
                                + report.getCertificateChainList().size()
                                + ")");
                appendCertificate(builder, chainReport);
                certCtr++;
            }
        }
        return builder;
    }

    private StringBuilder appendCertificate(StringBuilder builder, CertificateChainReport chain) {
        prettyAppend(
                builder,
                "Chain ordered",
                chain.getChainIsOrdered(),
                Objects.equals(chain.getChainIsOrdered(), Boolean.TRUE)
                        ? AnsiColor.GREEN
                        : AnsiColor.YELLOW);
        prettyAppend(
                builder,
                "Contains Trust Anchor",
                chain.getContainsTrustAnchor(),
                Objects.equals(chain.getContainsTrustAnchor(), Boolean.TRUE)
                        ? AnsiColor.RED
                        : AnsiColor.GREEN);
        prettyAppend(
                builder,
                "Generally Trusted",
                chain.getGenerallyTrusted(),
                Objects.equals(chain.getGenerallyTrusted(), Boolean.TRUE)
                        ? AnsiColor.GREEN
                        : AnsiColor.RED);
        prettyAppend(
                builder,
                "Custom Trusted",
                chain.getContainsCustomTrustAnchor(),
                Objects.equals(chain.getContainsCustomTrustAnchor(), Boolean.TRUE)
                        ? AnsiColor.GREEN
                        : AnsiColor.RED);

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
                if (certReport.getNotBefore() != null) {
                    if (certReport.getNotBefore().isBeforeNow()) {
                        prettyAppend(
                                builder,
                                "Valid From",
                                certReport.getNotBefore().toString(),
                                AnsiColor.GREEN);
                    } else {
                        prettyAppend(
                                builder,
                                "Valid From",
                                certReport.getNotBefore().toString() + " - NOT YET VALID",
                                AnsiColor.RED);
                    }
                }
                if (certReport.getNotAfter() != null) {
                    if (certReport.getNotAfter().isAfterNow()) {
                        prettyAppend(
                                builder,
                                "Valid Till",
                                certReport.getNotAfter().toString(),
                                AnsiColor.GREEN);
                    } else {
                        prettyAppend(
                                builder,
                                "Valid Till",
                                certReport.getNotAfter().toString() + " - EXPIRED",
                                AnsiColor.RED);
                    }
                }
                if (certReport.getNotBefore() != null
                        && certReport.getNotAfter() != null
                        && certReport.getNotAfter().isAfterNow()) {
                    int days = Days.daysBetween(DateTime.now(), certReport.getNotAfter()).getDays();
                    if (days < 1) {
                        prettyAppend(
                                builder,
                                "Expires in",
                                "<1 day! This certificate expires very soon",
                                AnsiColor.RED);
                    } else if (days < 3) {
                        prettyAppend(
                                builder,
                                "Expires in",
                                days + " days! This certificate expires soon",
                                AnsiColor.RED);
                    } else if (days < 14) {
                        prettyAppend(
                                builder,
                                "Expires in",
                                days + " days. This certificate expires soon",
                                AnsiColor.YELLOW);
                    } else if (days < 31) {
                        prettyAppend(
                                builder, "Expires in", days + " days.", AnsiColor.DEFAULT_COLOR);
                    } else if (days < 730) {
                        prettyAppend(builder, "Expires in", days + " days.", AnsiColor.GREEN);
                    } else if (Objects.equals(certReport.getLeafCertificate(), Boolean.TRUE)) {
                        prettyAppend(
                                builder,
                                "Expires in",
                                days + " days. This is usually too long for a leaf certificate",
                                AnsiColor.RED);
                    } else {
                        prettyAppend(builder, "Expires in", days / 365 + " years", AnsiColor.GREEN);
                    }
                }
                if (certReport.getPublicKey() != null) {
                    prettyAppendPublicKey(builder, certReport.getPublicKey());
                }
                if (certReport.getWeakDebianKey() != null) {
                    prettyAppend(
                            builder,
                            "Weak Debian Key",
                            certReport.getWeakDebianKey(),
                            certReport.getWeakDebianKey() ? AnsiColor.RED : AnsiColor.GREEN);
                }
                if (certReport.getSignatureAlgorithm() != null) {
                    prettyAppend(
                            builder,
                            "Signature Algorithm",
                            certReport.getSignatureAlgorithm().name());
                }
                if (certReport.getSignatureAlgorithm() != null) {
                    if (certReport.getHashAlgorithm() == HashAlgorithm.SHA1
                            || certReport.getHashAlgorithm() == HashAlgorithm.MD5) {
                        if (!certReport.isTrustAnchor() && !certReport.getSelfSigned()) {
                            prettyAppend(
                                    builder,
                                    "Hash Algorithm",
                                    certReport.getHashAlgorithm().name(),
                                    AnsiColor.RED);
                        } else {
                            prettyAppend(
                                    builder,
                                    "Hash Algorithm",
                                    certReport.getHashAlgorithm().name() + " - Not critical");
                        }
                    } else {
                        prettyAppend(
                                builder,
                                "Hash Algorithm",
                                certReport.getHashAlgorithm().name(),
                                AnsiColor.GREEN);
                    }
                }
                if (certReport.getExtendedValidation() != null) {
                    prettyAppend(
                            builder,
                            "Extended Validation",
                            certReport.getExtendedValidation(),
                            certReport.getExtendedValidation()
                                    ? AnsiColor.GREEN
                                    : AnsiColor.DEFAULT_COLOR);
                }
                if (certReport.getCertificateTransparency() != null) {
                    prettyAppend(
                            builder,
                            "Certificate Transparency",
                            certReport.getCertificateTransparency(),
                            certReport.getCertificateTransparency()
                                    ? AnsiColor.GREEN
                                    : AnsiColor.YELLOW);
                }

                if (certReport.getCrlSupported() != null) {
                    prettyAppend(
                            builder,
                            "CRL Supported",
                            certReport.getCrlSupported(),
                            certReport.getCrlSupported()
                                    ? AnsiColor.GREEN
                                    : AnsiColor.DEFAULT_COLOR);
                }
                if (certReport.getOcspSupported() != null) {
                    prettyAppend(
                            builder,
                            "OCSP Supported",
                            certReport.getOcspSupported(),
                            certReport.getOcspSupported() ? AnsiColor.GREEN : AnsiColor.YELLOW);
                }
                if (certReport.getOcspMustStaple() != null) {
                    prettyAppend(builder, "OCSP must Staple", certReport.getOcspMustStaple());
                }
                if (certReport.getRevoked() != null) {
                    prettyAppend(
                            builder,
                            "RevocationStatus",
                            certReport.getRevoked(),
                            certReport.getRevoked() ? AnsiColor.RED : AnsiColor.GREEN);
                }
                if (certReport.getDnsCAA() != null) {
                    prettyAppend(
                            builder,
                            "DNS CCA",
                            certReport.getDnsCAA(),
                            certReport.getDnsCAA() ? AnsiColor.GREEN : AnsiColor.DEFAULT_COLOR);
                }
                if (certReport.getRocaVulnerable() != null) {
                    prettyAppend(
                            builder,
                            "ROCA (simple)",
                            certReport.getRocaVulnerable(),
                            certReport.getRocaVulnerable() ? AnsiColor.RED : AnsiColor.GREEN);
                } else {
                    builder.append("ROCA (simple): not tested");
                }
                prettyAppendHexString(
                        builder,
                        "Fingerprint (SHA256)",
                        ArrayConverter.bytesToHexString(
                                certReport.getSHA256Fingerprint(), false, false));
            }
        }
        return builder;
    }

    private String prettyAppendPublicKey(StringBuilder builder, PublicKeyContainer publicKey) {
        if (publicKey instanceof DhPublicKey) {
            DhPublicKey dhPublicKey = (DhPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "Static Diffie Hellman");

            prettyAppendHexString(builder, "Modulus", dhPublicKey.getModulus().toString(16));
            prettyAppendHexString(builder, "Generator", dhPublicKey.getGenerator().toString(16));
            prettyAppendHexString(builder, "Y", dhPublicKey.getPublicKey().toString(16));
        } else if (publicKey instanceof DsaPublicKey) {
            DsaPublicKey dsaPublicKey = (DsaPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "DSA");
            prettyAppendHexString(builder, "Modulus", dsaPublicKey.getModulus().toString(16));
            prettyAppendHexString(builder, "Generator", dsaPublicKey.getGenerator().toString(16));
            prettyAppendHexString(builder, "Q", dsaPublicKey.getQ().toString(16));
            prettyAppendHexString(builder, "X", dsaPublicKey.getY().toString(16));
        } else if (publicKey instanceof RsaPublicKey) {
            RsaPublicKey rsaPublicKey = (RsaPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "RSA");
            prettyAppendHexString(builder, "Modulus", rsaPublicKey.getModulus().toString(16));
            prettyAppendHexString(
                    builder, "Public exponent", rsaPublicKey.getPublicExponent().toString(16));
        } else if (publicKey instanceof EcdhPublicKey) {
            EcdhPublicKey ecdhPublicKey = (EcdhPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "ECDH");
            prettyAppend(builder, "Group", ecdhPublicKey.getParameters().name());
            prettyAppendHexString(
                    builder, "Public Point", ecdhPublicKey.getPublicPoint().toString());
        } else if (publicKey instanceof EcdsaPublicKey) {
            EcdsaPublicKey ecdsaPublicKey = (EcdsaPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "ECDH/ECDSA");
            prettyAppend(builder, "Group", ecdsaPublicKey.getParameters().name());
            prettyAppendHexString(
                    builder, "Public Point", ecdsaPublicKey.getPublicPoint().toString());
        } else {
            builder.append(publicKey.toString()).append("\n");
        }
        return builder.toString();
    }

    public StringBuilder appendSession(StringBuilder builder) {
        prettyAppendHeading(builder, "Session");
        prettyAppend(
                builder,
                "Supports Session ID Resumption",
                TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION);
        if (report.getProtocolType() == ProtocolType.DTLS) {
            prettyAppend(
                    builder,
                    "DTLS cookie exchange in Session ID Resumption",
                    TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION);
        }
        prettyAppend(
                builder,
                "Issues Session Tickets",
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_EXTENSION);
        prettyAppend(
                builder,
                "Supports Session Ticket Resumption",
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION);
        if (report.getProtocolType() == ProtocolType.DTLS) {
            prettyAppend(
                    builder,
                    "DTLS cookie exchange in Session Ticket Resumption",
                    TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION);
        }
        prettyAppend(
                builder,
                "Issues TLS 1.3 Session Tickets directly after handshake",
                TlsAnalyzedProperty.ISSUES_TLS13_SESSION_TICKETS_AFTER_HANDSHAKE);
        prettyAppend(
                builder,
                "Issues TLS 1.3 Session Tickets with Application Data",
                TlsAnalyzedProperty.ISSUES_TLS13_SESSION_TICKETS_WITH_APPLICATION_DATA);
        prettyAppend(builder, "Supports TLS 1.3 PSK", TlsAnalyzedProperty.SUPPORTS_TLS13_PSK);
        prettyAppend(
                builder, "Supports TLS 1.3 PSK-DHE", TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE);
        prettyAppend(builder, "Supports 0-RTT", TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT);
        return builder;
    }

    public StringBuilder appendSessionTicketEval(StringBuilder builder) {
        prettyAppendHeading(builder, "SessionTicketEval");

        prettyAppendSubheading(builder, "Summary");
        prettyAppend(
                builder, "Ticket contains plain secret", TlsAnalyzedProperty.UNENCRYPTED_TICKET);
        prettyAppend(
                builder,
                "Ticket use default STEK (enc)",
                TlsAnalyzedProperty.DEFAULT_ENCRYPTION_KEY_TICKET);
        prettyAppend(
                builder,
                "Ticket use default STEK (MAC)",
                TlsAnalyzedProperty.DEFAULT_HMAC_KEY_TICKET);
        prettyAppend(builder, "No (full) MAC check", TlsAnalyzedProperty.NO_MAC_CHECK_TICKET);
        prettyAppend(
                builder, "Vulnerable to Padding Oracle", TlsAnalyzedProperty.PADDING_ORACLE_TICKET);

        prettyAppend(builder, "Tickets can be reused", TlsAnalyzedProperty.REUSABLE_TICKET);

        prettyAppend(
                builder,
                "Allows ciphersuite change",
                TlsAnalyzedProperty.ALLOW_CIPHERSUITE_CHANGE_TICKET);
        prettyAppend(
                builder,
                "Tickets resumable in different version",
                TlsAnalyzedProperty.ALLOW_VERSION_CHANGE_TICKET);

        prettyAppendSubheading(builder, "Details");
        // TODO use tables
        // once we have support for tables, most of the data below can be put into
        // tables
        // the columns would be the protocol version
        appendSessionTicketEval_VersionChange(builder);
        appendSessionTicketEval_CipherSuiteChange(builder);
        appendSessionTicketEval_ReusableTicket(builder);
        appendSessionTicketEval_Manipulation(builder);
        appendSessionTicketEval_PaddingOracle(builder);
        appendSessionTicketEval_Statistics(builder);
        appendSessionTicketEval_Unencrypted(builder);
        appendSessionTicketEval_ReusedKeystream(builder);
        appendSessionTicketEval_DefaultStek(builder);
        appendSessionTicketEval_DefaultMacStek(builder);
        return builder;
    }

    public StringBuilder appendSessionTicketEval_VersionChange(StringBuilder builder) {
        TestResult result = report.getResult(TlsAnalyzedProperty.ALLOW_VERSION_CHANGE_TICKET);
        if (result instanceof VersionDependentSummarizableResult) {
            var allowsVersionChange =
                    (VersionDependentSummarizableResult<VersionDependentTestResults>) result;
            for (Entry<ProtocolVersion, VersionDependentTestResults> versionResults :
                    allowsVersionChange.getResultMap().entrySet()) {
                VersionDependentTestResults versionResult = versionResults.getValue();
                prettyAppend(builder, "Resuming " + versionResults.getKey() + " Ticket in");
                if (versionResult.isExplicitSummary()) {
                    prettyAppend(builder, "\t" + versionResult.getSummarizedResult().toString());
                } else {
                    for (Entry<ProtocolVersion, TestResults> changeResult :
                            versionResult.getResultMap().entrySet()) {
                        prettyAppend(
                                builder,
                                "\t" + changeResult.getKey() + ": ",
                                changeResult.getValue().toString());
                    }
                }
            }
        }
        return builder;
    }

    public StringBuilder appendSessionTicketEval_CipherSuiteChange(StringBuilder builder) {
        TestResult result = report.getResult(TlsAnalyzedProperty.ALLOW_CIPHERSUITE_CHANGE_TICKET);
        if (result instanceof VersionDependentTestResults) {
            var allowsCipherSuiteChange = (VersionDependentTestResults) result;
            for (Entry<ProtocolVersion, TestResults> versionResults :
                    allowsCipherSuiteChange.getResultMap().entrySet()) {
                prettyAppend(
                        builder,
                        "Allows ciphersuite change [" + versionResults.getKey() + "]",
                        versionResults.getValue().toString());
            }
        }
        return builder;
    }

    public StringBuilder appendSessionTicketEval_ReusableTicket(StringBuilder builder) {
        TestResult result = report.getResult(TlsAnalyzedProperty.REUSABLE_TICKET);
        if (result instanceof VersionDependentTestResults) {
            var allowsReplayingTickets = (VersionDependentTestResults) result;

            for (Entry<ProtocolVersion, TestResults> versionResults :
                    allowsReplayingTickets.getResultMap().entrySet()) {
                prettyAppend(
                        builder,
                        "Tickets can be reused [" + versionResults.getKey() + "]",
                        versionResults.getValue().toString());
            }
        }
        return builder;
    }

    public StringBuilder appendSessionTicketEval_Manipulation(StringBuilder builder) {
        TestResult result = report.getResult(TlsAnalyzedProperty.NO_MAC_CHECK_TICKET);

        if (result instanceof VersionDependentResult) {
            var mainManipulationResult = (VersionDependentResult<TicketManipulationResult>) result;
            // have one map, such that the classes stay the same
            Map<ResponseFingerprint, Integer> manipulationClassifications = new HashMap<>();

            prettyAppendSubheading(builder, "Manipulation");
            // print brief overview
            for (Entry<ProtocolVersion, TicketManipulationResult> manipulationResult :
                    mainManipulationResult.getResultMap().entrySet()) {
                prettyAppend(
                        builder,
                        "Manipulation Overview "
                                + manipulationResult.getKey()
                                + ": "
                                + manipulationResult
                                        .getValue()
                                        .getResultsAsShortString(
                                                manipulationClassifications, true));
            }

            if (detail.getLevelValue() >= ScannerDetail.DETAILED.getLevelValue()) {
                for (Entry<ProtocolVersion, TicketManipulationResult> manipulationResult :
                        mainManipulationResult.getResultMap().entrySet()) {
                    prettyAppend(
                            builder,
                            "Manipulation Details "
                                    + manipulationResult.getKey()
                                    + ": "
                                    + manipulationResult
                                            .getValue()
                                            .getResultsAsShortString(
                                                    manipulationClassifications, false));
                }
            }

            // print legend
            for (Entry<ProtocolVersion, TicketManipulationResult> manipulationResult :
                    mainManipulationResult.getResultMap().entrySet()) {
                prettyAppend(
                        builder,
                        padToLength(
                                        TicketManipulationResult.CHR_ACCEPT
                                                + " ["
                                                + manipulationResult.getKey()
                                                + "]",
                                        10)
                                + "\t: "
                                + manipulationResult.getValue().getAcceptFingerprint());
            }
            for (Entry<ProtocolVersion, TicketManipulationResult> manipulationResult :
                    mainManipulationResult.getResultMap().entrySet()) {
                prettyAppend(
                        builder,
                        padToLength(
                                        TicketManipulationResult.CHR_ACCEPT_DIFFERENT_SECRET
                                                + " ["
                                                + manipulationResult.getKey()
                                                + "]",
                                        10)
                                + "\t: "
                                + manipulationResult
                                        .getValue()
                                        .getAcceptDifferentSecretFingerprint());
            }
            for (Entry<ProtocolVersion, TicketManipulationResult> manipulationResult :
                    mainManipulationResult.getResultMap().entrySet()) {
                prettyAppend(
                        builder,
                        padToLength(
                                        TicketManipulationResult.CHR_REJECT
                                                + " ["
                                                + manipulationResult.getKey()
                                                + "]",
                                        10)
                                + "\t: "
                                + manipulationResult.getValue().getRejectFingerprint());
            }

            for (Entry<ResponseFingerprint, Integer> entry :
                    manipulationClassifications.entrySet().stream()
                            .sorted((a, b) -> Integer.compare(a.getValue(), b.getValue()))
                            .toArray(Entry[]::new)) {
                String key;
                if (entry.getValue() < TicketManipulationResult.CHR_CLASSIFICATIONS.length()) {
                    key =
                            ""
                                    + TicketManipulationResult.CHR_CLASSIFICATIONS.charAt(
                                            entry.getValue());
                } else {
                    key = "" + entry.getValue();
                }
                prettyAppend(builder, padToLength(key, 10) + "\t: " + entry.getKey());
            }

            prettyAppend(
                    builder,
                    padToLength(TicketManipulationResult.CHR_NO_RESULT + "", 10)
                            + "\t: *not tested/no result*");
            prettyAppend(
                    builder,
                    padToLength(TicketManipulationResult.CHR_UNKNOWN + "", 10)
                            + "\t: *multiple classifications/no more chars left to classify*");
        }

        return builder;
    }

    public StringBuilder appendSessionTicketEval_PaddingOracle(StringBuilder builder) {
        TestResult result = report.getResult(TlsAnalyzedProperty.PADDING_ORACLE_TICKET);

        if (result instanceof VersionDependentResult) {
            prettyAppendSubSubheading(builder, "Padding Oracle");
            var mainPaddingOracleResult =
                    (VersionDependentResult<TicketPaddingOracleResult>) result;

            for (Entry<ProtocolVersion, TicketPaddingOracleResult> paddingResult :
                    mainPaddingOracleResult.getResultMap().entrySet()) {
                prettyAppendSubSubSubheading(builder, paddingResult.getKey().toString());
                prettyAppend(
                        builder,
                        "Overall Result",
                        paddingResult.getValue().getOverallResult().toString());
                if (paddingResult.getValue().getSecondVectorsWithRareResponses() != null) {
                    for (TicketPaddingOracleVectorSecond vector :
                            paddingResult.getValue().getSecondVectorsWithRareResponses()) {
                        prettyAppend(
                                builder,
                                "Possible Plaintext:",
                                String.format(
                                        "%02x%02x (XOR %02x%02x@%d)",
                                        vector.secondAssumedPlaintext,
                                        vector.lastAssumedPlaintext,
                                        vector.secondXorValue,
                                        vector.lastXorValue,
                                        vector.offset));
                    }
                }

                if (paddingResult.getValue().getPositionResults() != null) {
                    appendInformationLeakTestList(
                            builder,
                            paddingResult.getValue().getPositionResults().stream()
                                    .map(TicketPaddingOracleOffsetResult::getLastByteLeakTest)
                                    .collect(Collectors.toList()),
                            "Padding Oracle Details");
                }
            }
        }

        return builder;
    }

    public StringBuilder appendSessionTicketEval_Statistics(StringBuilder builder) {
        TestResult result = report.getResult(TlsAnalyzedProperty.STATISTICS_TICKET);
        if (result instanceof VersionDependentResult) {
            var statistics = (VersionDependentResult<SessionTicketAfterStats>) result;
            prettyAppendSubSubheading(builder, "Statistics");
            for (Entry<ProtocolVersion, SessionTicketAfterStats> afterResultEntry :
                    statistics.getResultMap().entrySet()) {
                ProtocolVersion version = afterResultEntry.getKey();
                SessionTicketAfterStats afterResult = afterResultEntry.getValue();
                prettyAppendSubSubSubheading(builder, version.toString());
                prettyAppend(builder, "Ticket length", afterResult.getTicketLengths());
                prettyAppend(
                        builder,
                        "Keyname/Prefix length",
                        String.valueOf(afterResult.getKeyNameLength()));
                prettyAppend(builder, "Found ASCII Strings", "");
                for (String found : afterResult.getAsciiStringsFound()) {
                    prettyAppend(builder, "", "[" + found.length() + " Bytes] \"" + found + "\"");
                }
            }
        }
        return builder;
    }

    public StringBuilder appendSessionTicketEval_Unencrypted(StringBuilder builder) {
        TestResult result = report.getResult(TlsAnalyzedProperty.UNENCRYPTED_TICKET);
        if (result instanceof VersionDependentSummarizableResult) {
            var unencrypted =
                    (VersionDependentSummarizableResult<DetailedResult<FoundSecret>>) result;
            if (unencrypted.getSummarizedResult() == TestResults.TRUE) {
                for (var entry : unencrypted.getResultMap().entrySet()) {
                    if (entry.getValue().getSummarizedResult() == TestResults.TRUE) {
                        prettyAppendSubSubheading(builder, entry.getKey().toString());
                        prettyAppend(
                                builder,
                                "Found Plain Secret",
                                entry.getValue().getDetails().toReportString());
                    }
                }
            }
        }
        return builder;
    }

    public StringBuilder appendSessionTicketEval_ReusedKeystream(StringBuilder builder) {
        TestResult result = report.getResult(TlsAnalyzedProperty.REUSED_KEYSTREAM_TICKET);
        if (result instanceof VersionDependentSummarizableResult) {
            var reusedKeystream =
                    (VersionDependentSummarizableResult<DetailedResult<FoundSecret>>) result;
            if (reusedKeystream.getSummarizedResult() == TestResults.TRUE) {
                prettyAppendSubSubheading(builder, "Reused Keystream");
                for (var entry : reusedKeystream.getResultMap().entrySet()) {
                    if (entry.getValue().getSummarizedResult() == TestResults.TRUE) {
                        prettyAppendSubSubheading(builder, entry.getKey().toString());
                        prettyAppend(
                                builder,
                                "Found Reused Keystream - Found Secret",
                                entry.getValue().getDetails().toReportString());
                    }
                }
            }
        }
        return builder;
    }

    public StringBuilder appendSessionTicketEval_DefaultStek(StringBuilder builder) {
        TestResult result = report.getResult(TlsAnalyzedProperty.DEFAULT_ENCRYPTION_KEY_TICKET);
        if (result instanceof VersionDependentSummarizableResult) {
            var defaultStek =
                    (VersionDependentSummarizableResult<DetailedResult<FoundDefaultStek>>) result;
            if (defaultStek.getSummarizedResult() == TestResults.TRUE) {
                prettyAppendSubSubheading(builder, "Default STEK");
                for (var entry : defaultStek.getResultMap().entrySet()) {
                    if (entry.getValue().getSummarizedResult() == TestResults.TRUE) {
                        FoundDefaultStek foundDefaultStek = entry.getValue().getDetails();
                        prettyAppendSubSubSubheading(builder, entry.getKey().toString());
                        prettyAppend(builder, "Found Format", foundDefaultStek.format.toString());
                        prettyAppend(
                                builder, "Found Algorithm", foundDefaultStek.algorithm.toString());
                        prettyAppend(
                                builder,
                                "Found Key",
                                ArrayConverter.bytesToHexString(
                                        foundDefaultStek.key, false, false));
                        prettyAppend(
                                builder, "Found Secret", foundDefaultStek.secret.toReportString());
                    }
                }
            }
        }
        return builder;
    }

    public StringBuilder appendSessionTicketEval_DefaultMacStek(StringBuilder builder) {
        TestResult result = report.getResult(TlsAnalyzedProperty.DEFAULT_HMAC_KEY_TICKET);
        if (result instanceof VersionDependentSummarizableResult) {
            var defaultMacStek =
                    (VersionDependentSummarizableResult<DetailedResult<FoundDefaultHmacKey>>)
                            result;
            if (defaultMacStek.getSummarizedResult() == TestResults.TRUE) {
                prettyAppendSubSubheading(builder, "Default MAC STEK");
                for (var entry : defaultMacStek.getResultMap().entrySet()) {
                    if (entry.getValue().getSummarizedResult() == TestResults.TRUE) {
                        FoundDefaultHmacKey foundDefaultHmacKey = entry.getValue().getDetails();
                        prettyAppendSubSubSubheading(builder, entry.getKey().toString());
                        prettyAppend(
                                builder, "Found Format", foundDefaultHmacKey.format.toString());
                        prettyAppend(
                                builder,
                                "Found Algorithm",
                                foundDefaultHmacKey.algorithm.toString());
                        prettyAppend(
                                builder,
                                "Found Key",
                                ArrayConverter.bytesToHexString(
                                        foundDefaultHmacKey.key, false, false));
                    }
                }
            }
        }
        return builder;
    }

    public StringBuilder appendGcm(StringBuilder builder) {
        prettyAppendHeading(builder, "GCM");
        prettyAppend(builder, "GCM Nonce reuse", TlsAnalyzedProperty.REUSES_GCM_NONCES);
        if (null == report.getGcmPattern()) {
            prettyAppend(builder, "GCM Pattern", (String) null);
        } else {
            switch (report.getGcmPattern()) {
                case AWKWARD:
                    prettyAppend(
                            builder,
                            "GCM Pattern",
                            report.getGcmPattern().name(),
                            AnsiColor.YELLOW);
                    break;
                case INCREMENTING:
                case RANDOM:
                    prettyAppend(
                            builder, "GCM Pattern", report.getGcmPattern().name(), AnsiColor.GREEN);
                    break;
                case REPEATING:
                    prettyAppend(
                            builder, "GCM Pattern", report.getGcmPattern().name(), AnsiColor.RED);
                    break;
                default:
                    prettyAppend(
                            builder,
                            "GCM Pattern",
                            report.getGcmPattern().name(),
                            AnsiColor.DEFAULT_COLOR);
                    break;
            }
        }
        prettyAppend(builder, "GCM Check", TlsAnalyzedProperty.MISSES_GCM_CHECKS);
        return builder;
    }

    public StringBuilder appendRecordFragmentation(StringBuilder builder) {
        prettyAppendHeading(builder, "Record Fragmentation");
        prettyAppend(
                builder,
                "Supports Record Fragmentation",
                TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION);
        return builder;
    }

    public StringBuilder appendIntolerances(StringBuilder builder) {
        prettyAppendHeading(builder, "Common Bugs [EXPERIMENTAL]");
        prettyAppend(builder, "Version Intolerant", TlsAnalyzedProperty.HAS_VERSION_INTOLERANCE);
        prettyAppend(
                builder,
                "CipherSuite Intolerant",
                TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE);
        prettyAppend(
                builder, "Extension Intolerant", TlsAnalyzedProperty.HAS_EXTENSION_INTOLERANCE);
        prettyAppend(
                builder,
                "CS Length Intolerant (>512 Byte)",
                TlsAnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE);
        prettyAppend(
                builder, "Compression Intolerant", TlsAnalyzedProperty.HAS_COMPRESSION_INTOLERANCE);
        prettyAppend(builder, "ALPN Intolerant", TlsAnalyzedProperty.HAS_ALPN_INTOLERANCE);
        prettyAppend(
                builder,
                "CH Length Intolerant",
                TlsAnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE);
        prettyAppend(
                builder, "NamedGroup Intolerant", TlsAnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE);
        prettyAppend(
                builder,
                "Empty last Extension Intolerant",
                TlsAnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE);
        prettyAppend(
                builder,
                "SigHashAlgo Intolerant",
                TlsAnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE);
        prettyAppend(
                builder,
                "Big ClientHello Intolerant",
                TlsAnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE);
        prettyAppend(
                builder,
                "2nd CipherSuite Byte Bug",
                TlsAnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG);
        prettyAppend(
                builder,
                "Ignores offered Cipher suites",
                TlsAnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES);
        prettyAppend(
                builder,
                "Reflects offered Cipher suites",
                TlsAnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES);
        prettyAppend(
                builder,
                "Ignores offered NamedGroups",
                TlsAnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS);
        prettyAppend(
                builder,
                "Ignores offered SigHashAlgos",
                TlsAnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS);
        prettyAppend(
                builder,
                "Grease CipherSuite Intolerant",
                TlsAnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE);
        prettyAppend(
                builder,
                "Grease NamedGroup Intolerant",
                TlsAnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE);
        prettyAppend(
                builder,
                "Grease SigHashAlgo Intolerant",
                TlsAnalyzedProperty.HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE);
        return builder;
    }

    public StringBuilder appendHelloRetry(StringBuilder builder) {
        prettyAppendHeading(builder, "TLS 1.3 Hello Retry Request");
        prettyAppend(
                builder,
                "Sends Hello Retry Request",
                TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST);
        prettyAppend(builder, "Issues Cookie", TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY);
        return builder;
    }

    public StringBuilder appendAttackVulnerabilities(StringBuilder builder) {
        prettyAppendHeading(builder, "Attack Vulnerabilities");
        if (report.getKnownPaddingOracleVulnerability() == null) {
            prettyAppend(
                    builder, "Padding Oracle", TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE);
        } else {
            prettyAppend(
                    builder,
                    "Padding Oracle",
                    "true - " + report.getKnownPaddingOracleVulnerability().getShortName(),
                    AnsiColor.RED);
        }
        prettyAppend(builder, "Bleichenbacher", TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER);
        prettyAppend(builder, "Raccoon", TlsAnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK);
        prettyAppend(builder, "Direct Raccoon", TlsAnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON);
        prettyAppend(builder, "CRIME", TlsAnalyzedProperty.VULNERABLE_TO_CRIME);
        prettyAppend(builder, "Breach", TlsAnalyzedProperty.VULNERABLE_TO_BREACH);
        prettyAppend(builder, "Invalid Curve", TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE);
        prettyAppend(
                builder,
                "Invalid Curve (ephemeral)",
                TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL);
        prettyAppend(
                builder,
                "Invalid Curve (twist)",
                TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST);
        prettyAppend(builder, "SSL Poodle", TlsAnalyzedProperty.VULNERABLE_TO_POODLE);
        prettyAppend(builder, "Logjam", TlsAnalyzedProperty.VULNERABLE_TO_LOGJAM);
        prettyAppend(builder, "Sweet 32", TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32);
        prettyAppend(builder, "General DROWN", TlsAnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN);
        prettyAppend(
                builder, "Extra Clear DROWN", TlsAnalyzedProperty.VULNERABLE_TO_EXTRA_CLEAR_DROWN);
        prettyAppend(builder, "Heartbleed", TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED);
        prettyAppend(builder, "EarlyCcs", TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS);
        prettyAppend(builder, "ALPACA", TlsAnalyzedProperty.ALPACA_MITIGATED);
        prettyAppend(builder, "Renegotiation Attack (ext)");
        prettyAppend(
                builder,
                "-1.hs without ext, 2.hs with ext",
                TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V1);
        prettyAppend(
                builder,
                "-1.hs with ext, 2.hs without ext",
                TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V2);
        prettyAppend(builder, "Renegotiation Attack (cs)");
        prettyAppend(
                builder,
                "-1.hs without cs, 2.hs with cs",
                TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V1);
        prettyAppend(
                builder,
                "-1.hs with cs, 2.hs without cs",
                TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V2);
        return builder;
    }

    public StringBuilder appendRaccoonAttackDetails(StringBuilder builder) {
        DecimalFormat decimalFormat = new DecimalFormat();
        decimalFormat.setMaximumFractionDigits(24);
        if ((report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK) == TestResults.TRUE
                        || detail.isGreaterEqualTo(ScannerDetail.DETAILED))
                && report.getRaccoonAttackProbabilities() != null) {
            prettyAppendHeading(builder, "Raccoon Attack Details");
            prettyAppend(
                    builder,
                    "Here we are calculating how likely it is that the attack can reach a critical block border.");
            prettyAppend(
                    builder,
                    "Available Injection points:",
                    (long) report.getRaccoonAttackProbabilities().size());
            if (report.getRaccoonAttackProbabilities().size() > 0) {
                prettyAppendSubheading(builder, "Probabilities");
                prettyAppend(
                        builder,
                        addIndentations("InjectionPoint") + "\t Leak" + "\tProbability",
                        AnsiColor.BOLD);
                for (RaccoonAttackProbabilities probabilities :
                        report.getRaccoonAttackProbabilities()) {
                    builder.append(
                            addIndentations(probabilities.getPosition().name())
                                    + "\t "
                                    + probabilities.getBitsLeaked()
                                    + "\t"
                                    + decimalFormat.format(probabilities.getChanceForEquation())
                                    + "\n");
                }
                if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                        || report.getResult(TlsAnalyzedProperty.SUPPORTS_PSK_DHE)
                                == TestResults.TRUE) {
                    prettyAppendSubheading(builder, "PSK Length Probabilities");
                    prettyAppend(
                            builder,
                            addIndentations("PSK Length")
                                    + addIndentations("BitLeak")
                                    + "Probability",
                            AnsiColor.BOLD);

                    for (RaccoonAttackProbabilities probabilities :
                            report.getRaccoonAttackProbabilities()) {

                        prettyAppendSubheading(builder, probabilities.getPosition().name());

                        for (RaccoonAttackPskProbabilities pskProbability :
                                probabilities.getPskProbabilityList()) {
                            prettyAppend(
                                    builder,
                                    addIndentations("" + pskProbability.getPskLength())
                                            + addIndentations(
                                                    ""
                                                            + pskProbability
                                                                    .getZeroBitsRequiredToNextBlockBorder())
                                            + decimalFormat.format(
                                                    pskProbability.getChanceForEquation()));
                        }
                    }
                }
            }
        }
        return builder;
    }

    public StringBuilder appendInformationLeakTestList(
            StringBuilder builder,
            List<InformationLeakTest<?>> informationLeakTestList,
            String heading) {
        prettyAppendHeading(builder, heading);
        if (informationLeakTestList == null || informationLeakTestList.isEmpty()) {
            prettyAppend(builder, "No test results");
        } else {
            for (InformationLeakTest<?> testResult : informationLeakTestList) {
                String valueP;
                if (testResult.getValueP() >= 0.001) {
                    valueP = String.format("%.3f", testResult.getValueP());
                } else {
                    valueP = "<0.001";
                }
                String resultString = testResult.getTestInfo().getPrintableName();
                if (testResult.getValueP() < 0.01) {
                    prettyAppend(
                            builder,
                            padToLength(resultString, 80)
                                    + " | "
                                    + padToLength(testResult.getEqualityError().name(), 25)
                                    + padToLength("| VULNERABLE", 25)
                                    + "| P: "
                                    + valueP,
                            AnsiColor.RED);
                } else if (testResult.getValueP() < 0.05) {
                    prettyAppend(
                            builder,
                            padToLength(resultString, 80)
                                    + " | "
                                    + padToLength(testResult.getEqualityError().name(), 25)
                                    + padToLength("| PROBABLY VULNERABLE", 25)
                                    + "| P: "
                                    + valueP,
                            AnsiColor.YELLOW);
                } else if (testResult.getValueP() < 1) {
                    prettyAppend(
                            builder,
                            padToLength(resultString, 80)
                                    + " | "
                                    + padToLength("No significant difference", 25)
                                    + padToLength("| NOT VULNERABLE", 25)
                                    + "| P: "
                                    + valueP,
                            AnsiColor.GREEN);
                } else {
                    prettyAppend(
                            builder,
                            padToLength(resultString, 80)
                                    + " | "
                                    + padToLength("No behavior difference", 25)
                                    + padToLength("| NOT VULNERABLE", 25)
                                    + "| P: "
                                    + valueP,
                            AnsiColor.GREEN);
                }

                if ((detail == ScannerDetail.DETAILED
                                && Objects.equals(
                                        testResult.isSignificantDistinctAnswers(), Boolean.TRUE))
                        || detail == ScannerDetail.ALL) {
                    if (testResult.getEqualityError() != EqualityError.NONE
                            || detail == ScannerDetail.ALL) {
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
            if (Objects.equals(
                    report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE),
                    TestResults.TRUE)) {
                prettyAppendHeading(builder, "PaddingOracle Details");

                if (report.getKnownPaddingOracleVulnerability() != null) {
                    KnownPaddingOracleVulnerability knownVulnerability =
                            report.getKnownPaddingOracleVulnerability();
                    prettyAppend(
                            builder,
                            "Identification",
                            knownVulnerability.getLongName(),
                            AnsiColor.RED);
                    prettyAppend(builder, "CVE", knownVulnerability.getCve(), AnsiColor.RED);
                    if (knownVulnerability.getStrength() != PaddingOracleStrength.WEAK) {
                        prettyAppend(
                                builder,
                                "Strength",
                                knownVulnerability.getStrength().name(),
                                AnsiColor.RED);
                    } else {
                        prettyAppend(
                                builder,
                                "Strength",
                                knownVulnerability.getStrength().name(),
                                AnsiColor.YELLOW);
                    }
                    if (knownVulnerability.isObservable()) {
                        prettyAppend(
                                builder,
                                "Observable",
                                "" + knownVulnerability.isObservable(),
                                AnsiColor.RED);
                    } else {
                        prettyAppend(
                                builder,
                                "Observable",
                                "" + knownVulnerability.isObservable(),
                                AnsiColor.YELLOW);
                    }
                    prettyAppend(builder, "\n");
                    prettyAppend(builder, knownVulnerability.getDescription());
                    prettyAppendHeading(builder, "Affected Products");

                    for (String s : knownVulnerability.getAffectedProducts()) {
                        prettyAppend(builder, s, AnsiColor.YELLOW);
                    }
                    prettyAppend(builder, "");
                    prettyAppend(
                            builder,
                            "If your tested software/hardware is not in this list, please let us know so we can add it here.");
                } else {
                    prettyAppend(
                            builder,
                            "Identification",
                            "Could not identify vulnerability. Please contact us if you know which software/hardware is generating this behavior.",
                            AnsiColor.YELLOW);
                }
            }
            prettyAppendHeading(builder, "PaddingOracle response map");
            if (report.getPaddingOracleTestResultList() == null
                    || report.getPaddingOracleTestResultList().isEmpty()) {
                prettyAppend(builder, "No test results");
            } else {
                prettyAppend(builder, "No vulnerability present to identify");

                // TODO this recopying is weird // this recopying is necessary to call
                // appendInformationLeakTestList,
                // otherwise there are problems with generic types
                List<InformationLeakTest<?>> informationLeakTestList = new LinkedList<>();
                informationLeakTestList.addAll(report.getPaddingOracleTestResultList());
                appendInformationLeakTestList(
                        builder, informationLeakTestList, "Padding Oracle Details");
            }
            prettyAppend(builder, "No test results");
        } catch (Exception e) {
            prettyAppend(builder, "Error:" + e.getMessage());
        }
        return builder;
    }

    public StringBuilder appendInformationLeakTestResult(
            StringBuilder builder, InformationLeakTest<?> informationLeakTest) {
        try {
            ResponseFingerprint defaultAnswer =
                    informationLeakTest.retrieveMostCommonAnswer().getFingerprint();
            List<VectorContainer> vectorContainerList =
                    informationLeakTest.getVectorContainerList();
            for (VectorContainer vectorContainer : vectorContainerList) {
                prettyAppend(
                        builder, "\t" + padToLength(vectorContainer.getVector().getName(), 40));
                for (ResponseCounter counter : vectorContainer.getDistinctResponsesCounterList()) {
                    AnsiColor color = AnsiColor.GREEN;
                    if (!counter.getFingerprint().equals(defaultAnswer)) {
                        // TODO received app data should also make this red
                        color = AnsiColor.RED;
                    }
                    prettyAppend(
                            builder,
                            "\t\t"
                                    + padToLength((counter.getFingerprint().toHumanReadable()), 40)
                                    + counter.getCounter()
                                    + "/"
                                    + counter.getTotal()
                                    + " ("
                                    + String.format("%.2f", counter.getProbability() * 100)
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
                List<InformationLeakTest<?>> informationLeakTestList = new LinkedList<>();
                informationLeakTestList.addAll(report.getBleichenbacherTestResultList());
                appendInformationLeakTestList(
                        builder, informationLeakTestList, "Bleichenbacher Details");
            }
            prettyAppend(builder, "No test results");
        } catch (Exception e) {
            prettyAppend(builder, "Error:" + e.getMessage());
        }
        return builder;
    }

    public StringBuilder appendEcPointFormats(StringBuilder builder) {
        prettyAppendHeading(builder, "Elliptic Curve Point Formats");
        prettyAppend(builder, "Uncompressed", TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT);
        prettyAppend(
                builder, "ANSIX962 Prime", TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME);
        prettyAppend(
                builder, "ANSIX962 Char2", TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2);
        prettyAppend(
                builder,
                "TLS 1.3 ANSIX962  SECP",
                TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION);
        return builder;
    }

    public StringBuilder appendInvalidCurveResults(StringBuilder builder) {
        prettyAppendHeading(builder, "Invalid Curve Details");
        boolean foundCouldNotTest = false;
        List<InvalidCurveResponse> invalidCurvesResults = report.getInvalidCurveTestResultList();
        if (report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE)
                        == TestResults.NOT_TESTED_YET
                && report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL)
                        == TestResults.NOT_TESTED_YET
                && report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST)
                        == TestResults.NOT_TESTED_YET) {
            prettyAppend(builder, "Not Tested");
        } else if (invalidCurvesResults == null) {
            prettyAppend(builder, "No test results");
        } else if (report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE)
                        == TestResults.FALSE
                && report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL)
                        == TestResults.FALSE
                && report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST)
                        == TestResults.FALSE
                && detail != ScannerDetail.ALL) {
            prettyAppend(builder, "No Vulnerabilities found");
        } else {
            for (InvalidCurveResponse response : invalidCurvesResults) {
                if (response.getChosenGroupReusesKey() == TestResults.COULD_NOT_TEST
                        || response.getShowsVulnerability() == TestResults.COULD_NOT_TEST
                        || response.getShowsVulnerability() == TestResults.COULD_NOT_TEST) {
                    foundCouldNotTest = true;
                }
                if ((response.getShowsVulnerability() == TestResults.TRUE
                                && detail.isGreaterEqualTo(ScannerDetail.NORMAL))
                        || (response.getShowsPointsAreNotValidated() == TestResults.TRUE
                                && detail.isGreaterEqualTo(ScannerDetail.DETAILED))
                        || detail == ScannerDetail.ALL) {
                    prettyAppend(builder, response.getVector().toString());
                    switch ((TestResults) response.getShowsPointsAreNotValidated()) {
                        case TRUE:
                            prettyAppend(
                                    builder, "Server did not validate points", AnsiColor.YELLOW);
                            break;
                        case FALSE:
                            prettyAppend(
                                    builder,
                                    "Server did validate points / uses invulnerable algorithm",
                                    AnsiColor.GREEN);
                            break;
                        default:
                            prettyAppend(
                                    builder, "Could not test point validation", AnsiColor.YELLOW);
                            break;
                    }
                    switch ((TestResults) response.getChosenGroupReusesKey()) {
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
                    switch ((TestResults) response.getShowsVulnerability()) {
                        case TRUE:
                            prettyAppend(builder, "Server is vulnerable", AnsiColor.RED);
                            break;
                        case FALSE:
                            prettyAppend(builder, "Server is not vulnerable", AnsiColor.GREEN);
                            break;
                        default:
                            prettyAppend(
                                    builder, "Could not test for vulnerability", AnsiColor.YELLOW);
                            break;
                    }
                    switch ((TestResults) response.getSideChannelSuspected()) {
                        case TRUE:
                            prettyAppend(builder, "Side Channel suspected", AnsiColor.RED);
                            break;
                        default:
                            prettyAppend(builder, "No Side Channel suspected", AnsiColor.GREEN);
                            break;
                    }
                }
            }
        }

        if (foundCouldNotTest && detail.isGreaterEqualTo(ScannerDetail.NORMAL)) {
            prettyAppend(builder, "Some tests did not finish", AnsiColor.YELLOW);
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
        Set<CipherSuite> ciphersuites = report.getSupportedCipherSuites();
        if (ciphersuites != null) {
            prettyAppendHeading(builder, "Supported Cipher suites");
            if (!ciphersuites.isEmpty()) {
                for (CipherSuite suite : ciphersuites) {
                    builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
                }
            } else {
                prettyAppend(builder, "-empty-", AnsiColor.RED);
            }
            if (report.getVersionSuitePairs() != null && !report.getVersionSuitePairs().isEmpty()) {
                for (VersionSuiteListPair versionSuitePair : report.getVersionSuitePairs()) {
                    prettyAppendHeading(
                            builder,
                            "Supported in "
                                    + toHumanReadable(versionSuitePair.getVersion())
                                    + (report.getResult(TlsAnalyzedProperty.ENFORCES_CS_ORDERING)
                                                    == TestResults.TRUE
                                            ? "(server order)"
                                            : ""));
                    for (CipherSuite suite : versionSuitePair.getCipherSuiteList()) {
                        builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
                    }
                }
            }

            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                prettyAppendHeading(builder, "Symmetric Supported");
                prettyAppend(builder, "Null", TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS);
                prettyAppend(builder, "Export", TlsAnalyzedProperty.SUPPORTS_EXPORT);
                prettyAppend(builder, "Anon", TlsAnalyzedProperty.SUPPORTS_ANON);
                prettyAppend(builder, "DES", TlsAnalyzedProperty.SUPPORTS_DES);
                prettyAppend(builder, "SEED", TlsAnalyzedProperty.SUPPORTS_SEED);
                prettyAppend(builder, "IDEA", TlsAnalyzedProperty.SUPPORTS_IDEA);
                prettyAppend(builder, "RC2", TlsAnalyzedProperty.SUPPORTS_RC2);
                prettyAppend(builder, "RC4", TlsAnalyzedProperty.SUPPORTS_RC4);
                prettyAppend(builder, "3DES", TlsAnalyzedProperty.SUPPORTS_3DES);
                prettyAppend(builder, "AES", TlsAnalyzedProperty.SUPPORTS_AES);
                prettyAppend(builder, "CAMELLIA", TlsAnalyzedProperty.SUPPORTS_CAMELLIA);
                prettyAppend(builder, "ARIA", TlsAnalyzedProperty.SUPPORTS_ARIA);
                prettyAppend(builder, "CHACHA20 POLY1305", TlsAnalyzedProperty.SUPPORTS_CHACHA);

                prettyAppendHeading(builder, "KeyExchange Supported");
                prettyAppend(builder, "RSA", TlsAnalyzedProperty.SUPPORTS_RSA);
                prettyAppend(builder, "STATIC-DH", TlsAnalyzedProperty.SUPPORTS_STATIC_DH);
                prettyAppend(builder, "DHE", TlsAnalyzedProperty.SUPPORTS_DHE);
                prettyAppend(builder, "ECDH", TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH);
                prettyAppend(builder, "ECDHE", TlsAnalyzedProperty.SUPPORTS_ECDHE);
                prettyAppend(builder, "GOST", TlsAnalyzedProperty.SUPPORTS_GOST);
                // prettyAppend(builder, "SRP", report.getSupportsSrp());
                prettyAppend(builder, "Kerberos", TlsAnalyzedProperty.SUPPORTS_KERBEROS);
                prettyAppend(builder, "Plain PSK", TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN);
                prettyAppend(builder, "PSK RSA", TlsAnalyzedProperty.SUPPORTS_PSK_RSA);
                prettyAppend(builder, "PSK DHE", TlsAnalyzedProperty.SUPPORTS_PSK_DHE);
                prettyAppend(builder, "PSK ECDHE", TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE);
                prettyAppend(builder, "Fortezza", TlsAnalyzedProperty.SUPPORTS_FORTEZZA);
                prettyAppend(builder, "New Hope", TlsAnalyzedProperty.SUPPORTS_NEWHOPE);
                prettyAppend(builder, "ECMQV", TlsAnalyzedProperty.SUPPORTS_ECMQV);
                prettyAppend(
                        builder, "TLS 1.3 PSK_DHE", TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE);

                prettyAppendHeading(builder, "KeyExchange Signatures");
                prettyAppend(builder, "RSA", TlsAnalyzedProperty.SUPPORTS_RSA_CERT);
                prettyAppend(builder, "ECDSA", TlsAnalyzedProperty.SUPPORTS_ECDSA);
                prettyAppend(builder, "DSS", TlsAnalyzedProperty.SUPPORTS_DSS);

                prettyAppendHeading(builder, "Cipher Types Supports");
                prettyAppend(builder, "Stream", TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS);
                prettyAppend(builder, "Block", TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS);
                prettyAppend(builder, "AEAD", TlsAnalyzedProperty.SUPPORTS_AEAD);
            }
            prettyAppendHeading(builder, "Perfect Forward Secrecy");
            prettyAppend(builder, "Supports PFS", TlsAnalyzedProperty.SUPPORTS_PFS);
            prettyAppend(builder, "Prefers PFS", TlsAnalyzedProperty.PREFERS_PFS);
            prettyAppend(builder, "Supports Only PFS", TlsAnalyzedProperty.SUPPORTS_ONLY_PFS);

            prettyAppendHeading(builder, "CipherSuite General");
            prettyAppend(
                    builder,
                    "Enforces CipherSuite ordering",
                    TlsAnalyzedProperty.ENFORCES_CS_ORDERING);
        }

        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            prettyAppendHeading(builder, "Symmetric Supported");
            prettyAppend(builder, "Null", TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS);
            prettyAppend(builder, "Export", TlsAnalyzedProperty.SUPPORTS_EXPORT);
            prettyAppend(builder, "Anon", TlsAnalyzedProperty.SUPPORTS_ANON);
            prettyAppend(builder, "DES", TlsAnalyzedProperty.SUPPORTS_DES);
            prettyAppend(builder, "SEED", TlsAnalyzedProperty.SUPPORTS_SEED);
            prettyAppend(builder, "IDEA", TlsAnalyzedProperty.SUPPORTS_IDEA);
            prettyAppend(builder, "RC2", TlsAnalyzedProperty.SUPPORTS_RC2);
            prettyAppend(builder, "RC4", TlsAnalyzedProperty.SUPPORTS_RC4);
            prettyAppend(builder, "3DES", TlsAnalyzedProperty.SUPPORTS_3DES);
            prettyAppend(builder, "AES", TlsAnalyzedProperty.SUPPORTS_AES);
            prettyAppend(builder, "CAMELLIA", TlsAnalyzedProperty.SUPPORTS_CAMELLIA);
            prettyAppend(builder, "ARIA", TlsAnalyzedProperty.SUPPORTS_ARIA);
            prettyAppend(builder, "CHACHA20 POLY1305", TlsAnalyzedProperty.SUPPORTS_CHACHA);

            prettyAppendHeading(builder, "KeyExchange Supported");
            prettyAppend(builder, "RSA", TlsAnalyzedProperty.SUPPORTS_RSA);
            prettyAppend(builder, "STATIC-DH", TlsAnalyzedProperty.SUPPORTS_STATIC_DH);
            prettyAppend(builder, "DHE", TlsAnalyzedProperty.SUPPORTS_DHE);
            prettyAppend(builder, "ECDH", TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH);
            prettyAppend(builder, "ECDHE", TlsAnalyzedProperty.SUPPORTS_ECDHE);
            prettyAppend(builder, "GOST", TlsAnalyzedProperty.SUPPORTS_GOST);
            // prettyAppend(builder, "SRP", report.getSupportsSrp());
            prettyAppend(builder, "Kerberos", TlsAnalyzedProperty.SUPPORTS_KERBEROS);
            prettyAppend(builder, "Plain PSK", TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN);
            prettyAppend(builder, "PSK RSA", TlsAnalyzedProperty.SUPPORTS_PSK_RSA);
            prettyAppend(builder, "PSK DHE", TlsAnalyzedProperty.SUPPORTS_PSK_DHE);
            prettyAppend(builder, "PSK ECDHE", TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE);
            prettyAppend(builder, "Fortezza", TlsAnalyzedProperty.SUPPORTS_FORTEZZA);
            prettyAppend(builder, "New Hope", TlsAnalyzedProperty.SUPPORTS_NEWHOPE);
            prettyAppend(builder, "ECMQV", TlsAnalyzedProperty.SUPPORTS_ECMQV);
            prettyAppend(builder, "TLS 1.3 PSK_DHE", TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE);

            prettyAppendHeading(builder, "KeyExchange Signatures");
            prettyAppend(builder, "RSA", TlsAnalyzedProperty.SUPPORTS_RSA_CERT);
            prettyAppend(builder, "ECDSA", TlsAnalyzedProperty.SUPPORTS_ECDSA);
            prettyAppend(builder, "DSS", TlsAnalyzedProperty.SUPPORTS_DSS);

            prettyAppendHeading(builder, "Cipher Types Supports");
            prettyAppend(builder, "Stream", TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS);
            prettyAppend(builder, "Block", TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS);
            prettyAppend(builder, "AEAD", TlsAnalyzedProperty.SUPPORTS_AEAD);
        }
        prettyAppendHeading(builder, "Perfect Forward Secrecy");
        prettyAppend(builder, "Supports PFS", TlsAnalyzedProperty.SUPPORTS_PFS);
        prettyAppend(builder, "Prefers PFS", TlsAnalyzedProperty.PREFERS_PFS);
        prettyAppend(builder, "Supports Only PFS", TlsAnalyzedProperty.SUPPORTS_ONLY_PFS);

        prettyAppendHeading(builder, "CipherSuite General");
        prettyAppend(
                builder, "Enforces CipherSuite ordering", TlsAnalyzedProperty.ENFORCES_CS_ORDERING);
        return builder;
    }

    public StringBuilder appendProtocolVersions(StringBuilder builder) {
        if (report.getSupportedProtocolVersions() != null) {
            prettyAppendHeading(builder, "Versions");
            prettyAppend(builder, "DTLS 1.0", TlsAnalyzedProperty.SUPPORTS_DTLS_1_0);
            prettyAppend(builder, "DTLS 1.2", TlsAnalyzedProperty.SUPPORTS_DTLS_1_2);
            prettyAppend(builder, "SSL 2.0", TlsAnalyzedProperty.SUPPORTS_SSL_2);
            prettyAppend(builder, "SSL 3.0", TlsAnalyzedProperty.SUPPORTS_SSL_3);
            prettyAppend(builder, "TLS 1.0", TlsAnalyzedProperty.SUPPORTS_TLS_1_0);
            prettyAppend(builder, "TLS 1.1", TlsAnalyzedProperty.SUPPORTS_TLS_1_1);
            prettyAppend(builder, "TLS 1.2", TlsAnalyzedProperty.SUPPORTS_TLS_1_2);
            prettyAppend(builder, "TLS 1.3", TlsAnalyzedProperty.SUPPORTS_TLS_1_3);
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 14", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 15", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 16", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 17", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 18", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 19", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 20", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 21", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 22", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 23", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 24", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 25", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 26", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 27", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 28", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28);
            }
        }
        return builder;
    }

    public StringBuilder appendHttps(StringBuilder builder) {
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_HTTPS) == TestResults.TRUE) {
            prettyAppendHeading(builder, "HSTS");
            try {

                if (report.getResult(TlsAnalyzedProperty.SUPPORTS_HSTS) == TestResults.TRUE) {
                    prettyAppend(builder, "HSTS", TlsAnalyzedProperty.SUPPORTS_HSTS);
                    prettyAppend(
                            builder,
                            "HSTS Preloading",
                            TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING);
                    prettyAppend(builder, "max-age (seconds)", (long) report.getHstsMaxAge());
                } else {
                    prettyAppend(builder, "Not supported");
                }
                prettyAppendHeading(builder, "HPKP");
                if (report.getResult(TlsAnalyzedProperty.SUPPORTS_HPKP) == TestResults.TRUE
                        || report.getResult(TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING)
                                == TestResults.TRUE) {
                    prettyAppend(builder, "HPKP", TlsAnalyzedProperty.SUPPORTS_HPKP);
                    prettyAppend(
                            builder,
                            "HPKP (report only)",
                            TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING);
                    prettyAppend(builder, "max-age (seconds)", (long) report.getHpkpMaxAge());

                    List<HpkpPin> normalPins = report.getNormalHpkpPins();
                    if (normalPins.size() > 0) {
                        prettyAppend(builder, "");
                        prettyAppend(builder, "HPKP-Pins:", AnsiColor.GREEN);
                        for (HpkpPin pin : normalPins) {
                            prettyAppend(builder, pin.toString());
                        }
                    }
                    List<HpkpPin> reportOnlyPins = report.getReportOnlyHpkpPins();
                    if (reportOnlyPins.size() > 0) {
                        prettyAppend(builder, "");
                        prettyAppend(builder, "Report Only HPKP-Pins:", AnsiColor.GREEN);
                        for (HpkpPin pin : reportOnlyPins) {
                            prettyAppend(builder, pin.toString());
                        }
                    }

                } else {
                    prettyAppend(builder, "Not supported");
                }
                prettyAppendHeading(builder, "HTTPS Response Header");
                for (HttpHeader header : report.getHttpHeader()) {
                    prettyAppend(
                            builder,
                            header.getHeaderName().getValue()
                                    + ":"
                                    + header.getHeaderValue().getValue());
                }
                prettyAppendHeading(builder, "HTTP False Start");
                prettyAppend(
                        builder, "HTTP False Start", TlsAnalyzedProperty.SUPPORTS_HTTP_FALSE_START);
            } catch (Exception e) {
                prettyAppend(builder, "Error: " + e.getMessage());
            }
        }

        return builder;
    }

    public StringBuilder appendExtensions(StringBuilder builder) {
        List<ExtensionType> extensions = report.getSupportedExtensions();
        if (extensions != null) {
            prettyAppendHeading(builder, "Supported Extensions");
            for (ExtensionType type : extensions) {
                builder.append(type.name()).append("\n");
            }
        }
        prettyAppendHeading(builder, "Extensions");
        prettyAppend(
                builder,
                "Secure Renegotiation",
                TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION);
        prettyAppend(
                builder,
                "Extended Master Secret",
                TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET);
        prettyAppend(builder, "Encrypt Then Mac", TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC);
        prettyAppend(builder, "Tokenbinding", TlsAnalyzedProperty.SUPPORTS_TOKENBINDING);
        prettyAppend(
                builder,
                "Certificate Status Request",
                TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST);
        prettyAppend(
                builder,
                "Certificate Status Request v2",
                TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2);
        prettyAppend(builder, "ESNI", TlsAnalyzedProperty.SUPPORTS_ESNI);

        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TOKENBINDING) == TestResults.TRUE) {
            prettyAppendHeading(builder, "Tokenbinding Version");
            for (TokenBindingVersion version : report.getSupportedTokenbindingVersions()) {
                builder.append(version.toString()).append("\n");
            }

            prettyAppendHeading(builder, "Tokenbinding Key Parameters");
            for (TokenBindingKeyParameters keyParameter :
                    report.getSupportedTokenbindingKeyParameters()) {
                builder.append(keyParameter.toString()).append("\n");
            }
        }
        appendTls13Groups(builder);
        appendGroups(builder);
        appendSignatureAndHashAlgorithms(builder);
        return builder;
    }

    public StringBuilder appendAlpacaAttack(StringBuilder builder) {
        prettyAppendHeading(builder, "Alpaca Details");
        prettyAppend(builder, "Strict ALPN", TlsAnalyzedProperty.STRICT_ALPN);
        prettyAppend(builder, "Strict SNI", TlsAnalyzedProperty.STRICT_SNI);
        prettyAppend(builder, "ALPACA Mitigation", TlsAnalyzedProperty.ALPACA_MITIGATED);
        return builder;
    }

    public StringBuilder appendAlpn(StringBuilder builder) {
        @SuppressWarnings("unchecked")
        List<String> alpns = report.getSupportedAlpnConstans();
        if (alpns != null) {
            prettyAppendHeading(builder, "ALPN");
            for (AlpnProtocol alpnProtocol : AlpnProtocol.values()) {
                if (alpnProtocol.isGrease()) {
                    continue;
                }
                if (alpns.contains(alpnProtocol.getConstant())) {
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

    public void appendRandomness(StringBuilder builder) {
        List<EntropyReport> entropyResults = report.getEntropyReports();
        if (entropyResults != null) {
            prettyAppendHeading(builder, "Entropy");
            prettyAppend(
                    builder, "Uses Unixtime", TlsAnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM);
            for (EntropyReport entropyReport : report.getEntropyReports()) {
                if (report.getProtocolType() == ProtocolType.TLS
                        && entropyReport.getType() == RandomType.COOKIE) {
                    continue;
                }
                prettyAppendSubheading(builder, entropyReport.getType().getHumanReadableName());
                prettyAppend(builder, "Datapoints", "" + entropyReport.getNumberOfValues());
                int bytesTotal = entropyReport.getNumberOfBytes();
                if (bytesTotal > 32000) {
                    prettyAppend(
                            builder, "Bytes total", "" + bytesTotal + " (good)", AnsiColor.GREEN);
                } else if (bytesTotal < 16000) {
                    prettyAppend(
                            builder,
                            "Bytes total",
                            "" + bytesTotal + " (not enough data collected)",
                            AnsiColor.RED);
                } else {
                    prettyAppend(
                            builder,
                            "Bytes total",
                            "" + bytesTotal + " (not siginificant)",
                            AnsiColor.YELLOW);
                }

                prettyAppend(builder, "Duplicates", entropyReport.isDuplicates());
                if (entropyReport.isDuplicates()) {
                    prettyAppend(
                            builder,
                            "Total duplicates",
                            "" + entropyReport.getNumberOfDuplicates());
                }
                prettyAppend(builder, "Failed Entropy Test", entropyReport.isFailedEntropyTest());
                prettyAppend(builder, "Failed Fourier Test", entropyReport.isFailedFourierTest());
                prettyAppend(
                        builder, "Failed Frequency Test", entropyReport.isFailedFrequencyTest());
                prettyAppend(builder, "Failed Runs Test", entropyReport.isFailedRunsTest());
                prettyAppend(
                        builder, "Failed Longest Run Test", entropyReport.isFailedLongestRunTest());
                prettyAppend(builder, "Failed Monobit Test", entropyReport.isFailedMonoBitTest());
                prettyAppend(
                        builder,
                        "Failed TemplateTests",
                        ""
                                + (Math.round(
                                                entropyReport.getFailedTemplateTestPercentage()
                                                        * 100.0)
                                        / 100.0)
                                + " %");
            }
        }
    }

    public void appendPublicKeyIssues(StringBuilder builder) {
        prettyAppendHeading(builder, "PublicKey Parameter");
        prettyAppend(builder, "EC PublicKey reuse", TlsAnalyzedProperty.REUSES_EC_PUBLICKEY);
        prettyAppend(builder, "DH PublicKey reuse", TlsAnalyzedProperty.REUSES_DH_PUBLICKEY);
        prettyAppend(
                builder, "Uses Common DH Primes", TlsAnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES);
        if (report.getCommonDhValues() != null && report.getCommonDhValues().size() != 0) {
            for (CommonDhValues value : report.getCommonDhValues()) {
                prettyAppend(builder, "\t" + value.getName(), AnsiColor.YELLOW);
            }
        }
        prettyAppend(
                builder, "Uses only prime moduli", TlsAnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI);
        prettyAppend(
                builder,
                "Uses only safe-prime moduli",
                TlsAnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI);
        if (report.getWeakestDhStrength() != null) {
            if (report.getWeakestDhStrength() < 1000) {
                prettyAppend(
                        builder, "DH Strength", "" + report.getWeakestDhStrength(), AnsiColor.RED);
            } else if (report.getWeakestDhStrength() < 2000) {
                prettyAppend(
                        builder,
                        "DH Strength",
                        "" + report.getWeakestDhStrength(),
                        AnsiColor.YELLOW);
            } else if (report.getWeakestDhStrength() < 4100) {
                prettyAppend(
                        builder,
                        "DH Strength",
                        "" + report.getWeakestDhStrength(),
                        AnsiColor.GREEN);
            } else {
                prettyAppend(
                        builder,
                        "DH Strength",
                        "" + report.getWeakestDhStrength(),
                        AnsiColor.YELLOW);
            }
        }
    }

    public void appendScoringResults(StringBuilder builder) {
        if (report.getScoreReport() == null) {
            return;
        }
        SiteReportRater rater;
        prettyAppendHeading(builder, "Scoring results");
        try {
            rater = DefaultRatingLoader.getServerReportRater("en");
            prettyAppend(builder, "Score: " + report.getScoreReport().getScore());
            if (!detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                return;
            }
            prettyAppend(builder, "");
            Recommendations recommendations = rater.getRecommendations();
            report.getScoreReport()
                    .getInfluencers()
                    .entrySet()
                    .forEach(
                            (entry) -> {
                                PropertyResultRatingInfluencer influencer = entry.getValue();
                                Recommendation recommendation =
                                        recommendations.getRecommendation(entry.getKey());
                                int scoreInfluence = 0;
                                StringBuilder additionalInfo = new StringBuilder();
                                if (influencer.getReferencedProperty() != null) {
                                    additionalInfo
                                            .append(" (Score: 0). -> See ")
                                            .append(influencer.getReferencedProperty())
                                            .append(" for more information");
                                } else {
                                    scoreInfluence = influencer.getInfluence();
                                    additionalInfo
                                            .append(" (Score: ")
                                            .append((scoreInfluence > 0 ? "+" : ""))
                                            .append(scoreInfluence);
                                    if (influencer.hasScoreCap()) {
                                        additionalInfo
                                                .append(", Score cap: ")
                                                .append(influencer.getScoreCap());
                                    }
                                    additionalInfo.append(")");
                                }
                                String result =
                                        recommendation.getShortName()
                                                + ": "
                                                + influencer.getResult()
                                                + additionalInfo;
                                if (scoreInfluence > 0) {
                                    prettyAppend(builder, result, AnsiColor.GREEN);
                                } else if (scoreInfluence < -50) {
                                    prettyAppend(builder, result, AnsiColor.RED);
                                } else if (scoreInfluence < 0) {
                                    prettyAppend(builder, result, AnsiColor.YELLOW);
                                }
                            });
        } catch (Exception ex) {
            LOGGER.error(ex);
            prettyAppend(builder, "Could not append scoring results", AnsiColor.RED);
        }
    }

    public void appendGuidelines(StringBuilder builder) {
        List<GuidelineReport> guidelineReports = report.getGuidelineReports();
        if (this.report.getGuidelineReports() != null
                && this.report.getGuidelineReports().size() > 0) {
            prettyAppendHeading(builder, "Guidelines");
            for (GuidelineReport report : guidelineReports) {
                appendGuideline(builder, report);
            }
        }
    }

    private void appendGuideline(StringBuilder builder, GuidelineReport guidelineReport) {
        prettyAppendSubheading(builder, "Guideline " + StringUtils.trim(guidelineReport.getName()));
        prettyAppend(builder, "Adhered: " + guidelineReport.getAdhered().size(), AnsiColor.GREEN);
        prettyAppend(builder, "Violated: " + guidelineReport.getViolated().size(), AnsiColor.RED);
        prettyAppend(
                builder, "Failed: " + guidelineReport.getFailedChecks().size(), AnsiColor.YELLOW);
        prettyAppend(builder, "Condition Not Met: " + guidelineReport.getConditionNotMet().size());
        if (this.detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            prettyAppend(builder, StringUtils.trim(guidelineReport.getLink()), AnsiColor.BLUE);

            if (this.detail.isGreaterEqualTo(ScannerDetail.ALL)) {
                prettyAppendSubSubheading(builder, "Passed Checks:");
                for (GuidelineCheckResult result : guidelineReport.getAdhered()) {
                    prettyAppend(builder, StringUtils.trim(result.getCheckName()), AnsiColor.GREEN);
                    prettyAppend(
                            builder,
                            "\t" + StringUtils.trim(result.toString()).replace("\n", "\n\t"));
                }
            }

            prettyAppendSubSubheading(builder, "Violated Checks:");
            for (GuidelineCheckResult result : guidelineReport.getViolated()) {
                prettyAppend(builder, StringUtils.trim(result.getCheckName()), AnsiColor.RED);
                prettyAppend(
                        builder, "\t" + StringUtils.trim(result.toString()).replace("\n", "\n\t"));
            }

            prettyAppendSubSubheading(builder, "Failed Checks:");
            for (GuidelineCheckResult result : guidelineReport.getFailedChecks()) {
                prettyAppend(builder, StringUtils.trim(result.getCheckName()), AnsiColor.YELLOW);
                prettyAppend(
                        builder, "\t" + StringUtils.trim(result.toString()).replace("\n", "\n\t"));
            }

            if (this.detail.isGreaterEqualTo(ScannerDetail.ALL)) {
                prettyAppendSubSubheading(builder, "Condition Not Met Checks:");
                for (GuidelineCheckResult result : guidelineReport.getConditionNotMet()) {
                    prettyAppend(builder, StringUtils.trim(result.getCheckName()));
                }
            }
        }
    }

    public void appendRecommendations(StringBuilder builder) {
        if (report.getScoreReport() == null) {
            return;
        }
        prettyAppendHeading(builder, "Recommendations");
        SiteReportRater rater;
        try {
            rater = DefaultRatingLoader.getServerReportRater("en");

            ScoreReport scoreReport = report.getScoreReport();
            Recommendations recommendations = rater.getRecommendations();
            LinkedHashMap<AnalyzedProperty, PropertyResultRatingInfluencer> influencers =
                    (LinkedHashMap<AnalyzedProperty, PropertyResultRatingInfluencer>)
                            scoreReport.getInfluencers();
            influencers.entrySet().stream()
                    .sorted(Map.Entry.comparingByValue())
                    .forEach(
                            (entry) -> {
                                PropertyResultRatingInfluencer influencer = entry.getValue();
                                if (influencer.isBadInfluence()
                                        || influencer.getReferencedProperty() != null) {
                                    Recommendation recommendation =
                                            recommendations.getRecommendation(entry.getKey());
                                    PropertyResultRecommendation resultRecommendation =
                                            recommendation.getPropertyResultRecommendation(
                                                    influencer.getResult());
                                    if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                                        printFullRecommendation(
                                                builder,
                                                recommendation,
                                                influencer,
                                                resultRecommendation);
                                    } else {
                                        printShortRecommendation(
                                                builder, influencer, resultRecommendation);
                                    }
                                }
                            });
        } catch (Exception ex) {
            prettyAppend(
                    builder, "Could not append recommendations - unrelated error", AnsiColor.RED);
            LOGGER.error("Could not append recommendations", ex);
        }
    }

    private void printFullRecommendation(
            StringBuilder builder,
            Recommendation recommendation,
            PropertyResultRatingInfluencer influencer,
            PropertyResultRecommendation resultRecommendation) {
        if (report.getScoreReport() == null) {
            return;
        }
        AnsiColor color = getRecommendationColor(influencer);
        prettyAppend(builder, "", color);
        prettyAppend(builder, recommendation.getShortName() + ": " + influencer.getResult(), color);
        int scoreInfluence = 0;
        String additionalInfo = "";
        SiteReportRater rater;

        try {
            rater = DefaultRatingLoader.getServerReportRater("en");

            if (influencer.getReferencedProperty() != null) {
                scoreInfluence =
                        rater.getRatingInfluencers()
                                .getPropertyRatingInfluencer(
                                        influencer.getReferencedProperty(),
                                        influencer.getReferencedPropertyResult())
                                .getInfluence();
                Recommendation r =
                        rater.getRecommendations()
                                .getRecommendation(influencer.getReferencedProperty());
                additionalInfo = " -> This score comes from \"" + r.getShortName() + "\"";
            } else {
                scoreInfluence = influencer.getInfluence();
            }
            prettyAppend(builder, "  Score: " + scoreInfluence + additionalInfo, color);
            if (influencer.hasScoreCap()) {
                prettyAppend(builder, "  Score cap: " + influencer.getScoreCap(), color);
            }
            prettyAppend(
                    builder, "  Information: " + resultRecommendation.getShortDescription(), color);
            prettyAppend(
                    builder,
                    "  Recommendation: " + resultRecommendation.getHandlingRecommendation(),
                    color);
        } catch (Exception ex) {
            prettyAppend(
                    builder,
                    "Could not append recommendations - recommendations or ratingInfluencers not found: "
                            + recommendation.getShortName(),
                    AnsiColor.RED);
            LOGGER.error(
                    "Could not append recommendations for: " + recommendation.getShortName(), ex);
        }
    }

    private void printShortRecommendation(
            StringBuilder builder,
            PropertyResultRatingInfluencer influencer,
            PropertyResultRecommendation resultRecommendation) {
        AnsiColor color = getRecommendationColor(influencer);
        prettyAppend(
                builder,
                resultRecommendation.getShortDescription()
                        + ". "
                        + resultRecommendation.getHandlingRecommendation(),
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

    public StringBuilder appendGroups(StringBuilder builder) {
        List<NamedGroup> namedGroups = report.getSupportedNamedGroups();
        if (namedGroups != null) {
            prettyAppendHeading(builder, "Supported Named Groups");
            if (namedGroups.size() > 0) {
                for (NamedGroup group : namedGroups) {
                    builder.append(group.name());
                    builder.append("\n");
                }
                if (report.getResult(TlsAnalyzedProperty.GROUPS_DEPEND_ON_CIPHER)
                        == TestResults.TRUE) {
                    prettyAppend(builder, "Not all Groups are supported for all Cipher Suites");
                }
                if (report.getResult(TlsAnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY)
                        == TestResults.TRUE) {
                    prettyAppend(
                            builder,
                            "Groups required for ECDSA validation are not enforced",
                            AnsiColor.YELLOW);
                }
                if (detail == ScannerDetail.ALL) {
                    prettyAppendHeading(builder, "Witnesses");
                    for (NamedGroupWitness witness :
                            report.getSupportedNamedGroupsWitnesses().values()) {
                        builder.append(
                                "SKE: "
                                        + witness.getEcdhPublicKeyGroup()
                                        + " Cert:"
                                        + witness.getCertificateGroup()
                                        + " CS:"
                                        + witness.getCipherSuites()
                                        + "\n");
                    }
                }
                prettyAppendHeading(builder, "NamedGroups General");
                prettyAppend(
                        builder,
                        "Enforces client's named group ordering",
                        TlsAnalyzedProperty.ENFORCES_NAMED_GROUP_ORDERING);
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    public StringBuilder appendSignatureAndHashAlgorithms(StringBuilder builder) {
        List<SignatureAndHashAlgorithm> algorithms =
                report.getSupportedSignatureAndHashAlgorithms();
        if (algorithms != null) {
            prettyAppendHeading(builder, "Supported Signature and Hash Algorithms");
            if (report.getSupportedSignatureAndHashAlgorithms().size() > 0) {
                for (SignatureAndHashAlgorithm algorithm :
                        report.getSupportedSignatureAndHashAlgorithms()) {
                    prettyAppend(builder, algorithm.toString());
                }
                prettyAppendHeading(builder, "Signature and Hash Algorithms General");
                prettyAppend(
                        builder,
                        "Enforces client's signature has algorithm ordering",
                        TlsAnalyzedProperty.ENFORCES_SIGNATURE_HASH_ALGORITHM_ORDERING);
            } else {
                builder.append("none\n");
            }
        }
        List<SignatureAndHashAlgorithm> algorithmsTls13 =
                report.getSupportedSignatureAndHashAlgorithmsTls13();
        if (algorithmsTls13 != null) {
            prettyAppendHeading(builder, "Supported Signature and Hash Algorithms TLS 1.3");
            if (report.getSupportedSignatureAndHashAlgorithmsTls13().size() > 0) {
                for (SignatureAndHashAlgorithm algorithm :
                        report.getSupportedSignatureAndHashAlgorithmsTls13()) {
                    prettyAppend(builder, algorithm.toString());
                }
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    public StringBuilder appendCompressions(StringBuilder builder) {
        prettyAppendHeading(builder, "Supported Compressions");
        List<CompressionMethod> compressions = report.getSupportedCompressionMethods();
        if (compressions != null) {

            for (CompressionMethod compression : compressions) {
                prettyAppend(builder, compression.name());
            }
        }
        return builder;
    }

    public StringBuilder appendTls13Groups(StringBuilder builder) {
        List<NamedGroup> tls13Groups = report.getSupportedTls13Groups();
        if (tls13Groups != null) {
            prettyAppendHeading(builder, "TLS 1.3 Named Groups");
            if (tls13Groups.size() > 0) {
                for (NamedGroup group : tls13Groups) {
                    builder.append(group.name()).append("\n");
                }
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    public void appendPerformanceData(StringBuilder builder) {
        if (detail.isGreaterEqualTo(ScannerDetail.ALL)) {
            prettyAppendHeading(builder, "Scanner Performance");
            try {
                if (report.getProtocolType() == ProtocolType.TLS) {
                    prettyAppend(
                            builder,
                            "TCP connections",
                            String.valueOf(report.getPerformedConnections()));
                }
                prettyAppendSubheading(builder, "Probe execution performance");
                for (PerformanceData data : report.getProbePerformanceData()) {
                    Period period = new Period(data.getStopTime() - data.getStartTime());
                    prettyAppend(
                            builder,
                            padToLength(data.getType().getName(), 25)
                                    + " "
                                    + PeriodFormat.getDefault().print(period));
                }
            } catch (Exception e) {
                prettyAppend(builder, "Error: " + e.getMessage());
            }
        } else {
            LOGGER.debug("Not printing performance data.");
        }
    }
}
