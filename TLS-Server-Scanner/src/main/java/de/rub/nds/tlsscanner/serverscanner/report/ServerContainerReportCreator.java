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
import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.scanner.core.report.PerformanceData;
import de.rub.nds.scanner.core.report.PrintingScheme;
import de.rub.nds.scanner.core.report.container.HeadlineContainer;
import de.rub.nds.scanner.core.report.container.KeyValueContainer;
import de.rub.nds.scanner.core.report.container.ListContainer;
import de.rub.nds.scanner.core.report.container.ReportContainer;
import de.rub.nds.scanner.core.report.container.TextContainer;
import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.scanner.core.report.rating.PropertyResultRecommendation;
import de.rub.nds.scanner.core.report.rating.Recommendation;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.scanner.core.report.rating.SiteReportRater;
import de.rub.nds.tlsattacker.core.constants.AlpnProtocol;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.DefaultPrintingScheme;
import de.rub.nds.tlsscanner.core.report.TlsReportCreator;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.prime.CommonDhValues;
import de.rub.nds.tlsscanner.serverscanner.probe.namedgroup.NamedGroupWitness;
import de.rub.nds.tlsscanner.serverscanner.report.rating.DefaultRatingLoader;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.Period;
import org.joda.time.format.PeriodFormat;

/** TODO: Need to be completed. */
public class ServerContainerReportCreator extends TlsReportCreator<ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerContainerReportCreator(ScannerDetail detail) {
        super(detail, DefaultPrintingScheme.getDefaultPrintingScheme());
    }

    public ServerContainerReportCreator(ScannerDetail detail, PrintingScheme scheme) {
        super(detail, scheme);
    }

    public ReportContainer createReport(ServerReport report) {
        ListContainer container = new ListContainer();
        container.add(
                new TextContainer(
                        "Report for " + report.getHost() + ":" + report.getPort(),
                        AnsiColor.DEFAULT_COLOR));
        if (report.getServerIsAlive() == Boolean.FALSE) {
            container.add(
                    new TextContainer(
                            "Cannot reach the Server. Is it online?", AnsiColor.DEFAULT_COLOR));
            return container;
        }
        if (report.getSpeaksProtocol() == Boolean.FALSE) {
            container.add(
                    new TextContainer(
                            "Server does not seem to support "
                                    + report.getProtocolType().getName()
                                    + " on the scanned port",
                            AnsiColor.DEFAULT_COLOR));
            return container;
        }
        container.add(createProtocolVersionContainer(report));
        container.add(createCipherSuiteContainer(report));
        container.add(createExtensionsContainer(report));
        container.add(createCompressionContainer(report));
        container.add(createEcPointFormatsContainer(report));
        container.add(createRecordFragmentationContainer(report));
        container.add(createAlpnContainer(report));
        container.add(createIntolerancesContainer(report));
        container.add(createHelloRetryContainer(report));
        container.add(createAttackVulnerabilitiesContainer(report));
        container.add(createAlpacaContainer(report));
        // container.add(createBleichenbacherOracleContainer(report));
        // container.add(createPaddingOracleContainer(report));
        // container.add(createDirectRaccoonResultsContainer(report));
        // container.add(createInvalidCurveResultsContainer(report));
        // container.add(createRaccoonResultsContainer(report));
        container.add(createCertificateContainer(report));
        // container.add(createOcspContainer(report));
        // container.add(createCertificateTransparencyContainer(report));
        // container.add(createSessionContainer(report));
        // container.add(createRenegotiationContainer(report));
        container.add(createHttpsContainer(report));
        // container.add(createRandomnessContainer(report));
        container.add(createPublicKeyIssuesContainer(report));
        container.add(createClientAuthenticationContainer(report));
        // container.add(createDtlsContainer(report));
        container.add(createScoringResultsContainer(report));
        container.add(createRecommendationsContainer(report));
        // container.add(createGuidelinesContainer(report));
        if (report.getProtocolType() == ProtocolType.DTLS) {
            container.add(createDtlsPortContainer(report));
            container.add(createDtlsReorderingContainer(report));
            container.add(createDtlsFragmenatationContainer(report));
            container.add(createDtlsCookieContainer(report));
            container.add(createDtlsMessageSequenceNumberContainer(report));
            container.add(createDtlsRetransmissionsContainer(report));
            container.add(createDtlsBugsContainer(report));
        }
        container.add(createPerformanceDataContainer(report));
        return container;
    }

    protected ReportContainer createDtlsPortContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("DTLS Port Analysis"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.CHANGES_PORT, report));
        if (report.getResult(TlsAnalyzedProperty.CHANGES_PORT) == TestResults.TRUE) {
            container.add(
                    createKeyValueContainer(
                            TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS, report));
        }
        return container;
    }

    protected ReportContainer createDtlsCookieContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("DTLS Hello Verify Request"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.HAS_HVR_RETRANSMISSIONS, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.HAS_COOKIE_CHECKS, report));
        if (report.getCookieLength() != null) {
            container.add(
                    createDefaultKeyValueContainer(
                            "Cookie length", report.getCookieLength().toString()));
        }
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.USES_IP_ADDRESS_FOR_COOKIE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.USES_PORT_FOR_COOKIE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.USES_VERSION_FOR_COOKIE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.USES_RANDOM_FOR_COOKIE, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.USES_SESSION_ID_FOR_COOKIE, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE, report));
        return container;
    }

    private ReportContainer createExtensionsContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        if (report.getSupportedExtensions() != null) {
            container.add(new HeadlineContainer("Supported Extensions"));
            for (ExtensionType type : report.getSupportedExtensions()) {
                container.add(new TextContainer(type.name(), AnsiColor.DEFAULT_COLOR));
            }
        }
        container.add(new HeadlineContainer("Extensions"));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_TOKENBINDING, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_ESNI, report));
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TOKENBINDING) == TestResults.TRUE) {
            container.add(new HeadlineContainer("Tokenbinding Version"));
            for (TokenBindingVersion version : report.getSupportedTokenbindingVersions()) {
                container.add(new TextContainer(version.toString(), AnsiColor.DEFAULT_COLOR));
            }

            container.add(new HeadlineContainer("Tokenbinding Key Parameters"));
            for (TokenBindingKeyParameters keyParameter :
                    report.getSupportedTokenbindingKeyParameters()) {
                container.add(new TextContainer(keyParameter.toString(), AnsiColor.DEFAULT_COLOR));
            }
        }
        appendTLS13Groups(report, container);
        appendCurves(report, container);
        appendSignatureAndHashAlgorithms(report, container);
        return container;
    }

    private void appendTLS13Groups(ServerReport report, ListContainer container) {
        if (report.getSupportedTls13Groups() != null) {
            container.add(new HeadlineContainer("TLS 1.3 Named Groups"));
            if (!report.getSupportedTls13Groups().isEmpty()) {
                for (NamedGroup group : report.getSupportedTls13Groups()) {
                    container.add(new TextContainer(group.name(), AnsiColor.DEFAULT_COLOR));
                }
            } else {
                container.add(new TextContainer("none", AnsiColor.DEFAULT_COLOR));
            }
        }
    }

    private void appendCurves(ServerReport report, ListContainer container) {
        if (report.getSupportedNamedGroups() != null) {
            container.add(new HeadlineContainer("Supported Named Groups"));
            if (!report.getSupportedNamedGroups().isEmpty()) {
                for (NamedGroup group : report.getSupportedNamedGroups()) {
                    container.add(new TextContainer(group.name(), AnsiColor.DEFAULT_COLOR));
                }
                if (report.getResult(TlsAnalyzedProperty.GROUPS_DEPEND_ON_CIPHER)
                        == TestResults.TRUE) {
                    container.add(
                            new TextContainer(
                                    "Not all Groups are supported for all Cipher Suites",
                                    AnsiColor.DEFAULT_COLOR));
                }
                if (report.getResult(TlsAnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY)
                        == TestResults.TRUE) {
                    container.add(
                            new TextContainer(
                                    "Groups required for ECDSA validation are not enforced",
                                    AnsiColor.YELLOW));
                }
                if (detail == ScannerDetail.ALL) {
                    ListContainer curveDetails = new ListContainer(1);
                    container.add(curveDetails);
                    curveDetails.add(new HeadlineContainer("Witnesses"));
                    for (NamedGroupWitness witness :
                            report.getSupportedNamedGroupsWitnesses().values()) {
                        curveDetails.add(
                                createDefaultTextContainer(
                                        "SKE: "
                                                + witness.getEcdhPublicKeyGroup()
                                                + " Cert:"
                                                + witness.getCertificateGroup()
                                                + " CS:"
                                                + witness.getCipherSuites()));
                    }
                }
            } else {
                container.add(new TextContainer("none", AnsiColor.DEFAULT_COLOR));
            }
        }
    }

    private void appendSignatureAndHashAlgorithms(ServerReport report, ListContainer container) {
        if (report.getSupportedSignatureAndHashAlgorithms() != null) {
            container.add(new HeadlineContainer("Supported Signature and Hash Algorithms"));
            if (!report.getSupportedSignatureAndHashAlgorithms().isEmpty()) {
                for (SignatureAndHashAlgorithm algorithm :
                        report.getSupportedSignatureAndHashAlgorithms()) {
                    container.add(createDefaultTextContainer(algorithm.toString()));
                }
            } else {
                container.add(createDefaultTextContainer("none"));
            }
        }
    }

    private ReportContainer createEcPointFormatsContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Elliptic Curve Point Formats"));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION, report));
        return container;
    }

    private ReportContainer createIntolerancesContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Common Bugs [EXPERIMENTAL]"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.HAS_VERSION_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.HAS_EXTENSION_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.HAS_COMPRESSION_INTOLERANCE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.HAS_ALPN_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE,
                        report));
        return container;
    }

    private ReportContainer createHelloRetryContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("TLS 1.3 Hello Retry Request"));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY, report));
        return container;
    }

    private ReportContainer createAttackVulnerabilitiesContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Attack Vulnerabilities"));
        if (report.getKnownPaddingOracleVulnerability() == null) {
            container.add(
                    createKeyValueContainer(
                            TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE, report));
        } else {
            container.add(
                    new KeyValueContainer(
                            "Padding Oracle",
                            AnsiColor.DEFAULT_COLOR,
                            report.getKnownPaddingOracleVulnerability().getShortName(),
                            AnsiColor.RED));
        }
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_BREACH, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_POODLE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_LOGJAM, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.VULNERABLE_TO_EXTRA_CLEAR_DROWN, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.ALPACA_MITIGATED, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V1,
                        report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V2,
                        report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V1,
                        report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V2,
                        report));
        return container;
    }

    private ReportContainer createAlpnContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        if (report.getSupportedAlpnConstans() == null) {
            return container;
        }
        container.add(new HeadlineContainer("ALPN"));
        for (AlpnProtocol alpnProtocol : AlpnProtocol.values()) {
            if (alpnProtocol.isGrease()) {
                continue;
            }
            if (report.getSupportedAlpnConstans().contains(alpnProtocol.getConstant())) {
                container.add(
                        new KeyValueContainer(
                                alpnProtocol.getPrintableName(),
                                AnsiColor.DEFAULT_COLOR,
                                "true",
                                AnsiColor.DEFAULT_COLOR));
            } else {
                if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                    container.add(
                            new KeyValueContainer(
                                    alpnProtocol.getPrintableName(),
                                    AnsiColor.DEFAULT_COLOR,
                                    "false",
                                    AnsiColor.DEFAULT_COLOR));
                }
            }
        }

        return container;
    }

    private ReportContainer createHttpsContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_HTTPS) == TestResults.TRUE) {
            container.add(new HeadlineContainer("HSTS"));
            try {

                if (report.getResult(TlsAnalyzedProperty.SUPPORTS_HSTS) == TestResults.TRUE) {
                    container.add(
                            createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_HSTS, report));
                    container.add(
                            createKeyValueContainer(
                                    TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING, report));
                    container.add(
                            createDefaultKeyValueContainer(
                                    "max-age (seconds)", String.valueOf(report.getHstsMaxAge())));
                } else {
                    container.add(createDefaultTextContainer("Not supported"));
                }
                container.add(new HeadlineContainer("HPKP"));
                if (report.getResult(TlsAnalyzedProperty.SUPPORTS_HPKP) == TestResults.TRUE
                        || report.getResult(TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING)
                                == TestResults.TRUE) {
                    container.add(
                            createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_HPKP, report));
                    container.add(
                            createKeyValueContainer(
                                    TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING, report));
                    container.add(
                            createDefaultKeyValueContainer(
                                    "max-age (seconds)", String.valueOf(report.getHpkpMaxAge())));
                    if (!report.getNormalHpkpPins().isEmpty()) {
                        container.add(
                                new KeyValueContainer(
                                        "HPKP-Pins",
                                        AnsiColor.DEFAULT_COLOR,
                                        report.getNormalHpkpPins().toString(),
                                        AnsiColor.GREEN));
                    }
                    if (!report.getReportOnlyHpkpPins().isEmpty()) {
                        container.add(
                                new KeyValueContainer(
                                        "Report Only HPKP-Pins",
                                        AnsiColor.DEFAULT_COLOR,
                                        report.getReportOnlyHpkpPins().toString(),
                                        AnsiColor.GREEN));
                    }

                } else {
                    container.add(createDefaultTextContainer("Not supported"));
                }
                container.add(new HeadlineContainer("HTTPS Response Header"));
                for (HttpHeader header : report.getHttpHeader()) {
                    container.add(
                            createDefaultKeyValueContainer(
                                    header.getHeaderName().getValue(),
                                    header.getHeaderValue().getValue()));
                }
                container.add(new HeadlineContainer("HTTP False Start"));
                container.add(
                        createKeyValueContainer(
                                TlsAnalyzedProperty.SUPPORTS_HTTP_FALSE_START, report));
            } catch (Exception e) {
                container.add(createDefaultTextContainer("Error: " + e.getMessage()));
            }
        }
        return container;
    }

    private ReportContainer createPublicKeyIssuesContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("PublicKy Parameter"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.REUSES_EC_PUBLICKEY, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, report));
        if (report.getCommonDhValues() != null && report.getCommonDhValues().size() != 0) {
            for (CommonDhValues value : report.getCommonDhValues()) {
                container.add(new TextContainer(value.getName(), AnsiColor.YELLOW));
            }
        }
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI, report));
        if (report.getWeakestDhStrength() != null) {
            if (report.getWeakestDhStrength() < 1000) {
                container.add(
                        new KeyValueContainer(
                                "DH Strength",
                                AnsiColor.DEFAULT_COLOR,
                                String.valueOf(report.getWeakestDhStrength()),
                                AnsiColor.RED));
            } else if (report.getWeakestDhStrength() < 2000) {
                container.add(
                        new KeyValueContainer(
                                "DH Strength",
                                AnsiColor.DEFAULT_COLOR,
                                String.valueOf(report.getWeakestDhStrength()),
                                AnsiColor.YELLOW));
            } else if (report.getWeakestDhStrength() < 4100) {
                container.add(
                        new KeyValueContainer(
                                "DH Strength",
                                AnsiColor.DEFAULT_COLOR,
                                String.valueOf(report.getWeakestDhStrength()),
                                AnsiColor.GREEN));
            } else {
                container.add(
                        new KeyValueContainer(
                                "DH Strength",
                                AnsiColor.DEFAULT_COLOR,
                                String.valueOf(report.getWeakestDhStrength()),
                                AnsiColor.YELLOW));
            }
        }
        return container;
    }

    private ReportContainer createClientAuthenticationContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Client authentication"));
        container.add(
                createDefaultKeyValueContainer(
                        "Supported", String.valueOf(report.getCcaSupported())));
        container.add(
                createDefaultKeyValueContainer(
                        "Required", String.valueOf(report.getCcaRequired())));

        return container;
    }

    private ReportContainer createScoringResultsContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Scoring results"));
        SiteReportRater rater;
        try {
            rater = DefaultRatingLoader.getServerReportRater("en");
            ScoreReport scoreReport = rater.getScoreReport(report.getResultMap());
            container.add(
                    createDefaultKeyValueContainer(
                            "Score", String.valueOf(scoreReport.getScore())));
            if (!detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                return container;
            }
            scoreReport
                    .getInfluencers()
                    .forEach(
                            (key, influencer) -> {
                                Recommendation recommendation =
                                        rater.getRecommendations().getRecommendation(key);
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
                                    container.add(new TextContainer(result, AnsiColor.GREEN));
                                } else if (scoreInfluence < -50) {
                                    container.add(new TextContainer(result, AnsiColor.RED));
                                } else if (scoreInfluence < 0) {
                                    container.add(new TextContainer(result, AnsiColor.YELLOW));
                                }
                            });
        } catch (Exception ex) {
            LOGGER.error(ex);
            container.add(new TextContainer("Could not append scoring results", AnsiColor.RED));
        }
        return container;
    }

    private ReportContainer createRecommendationsContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Recommendations"));
        SiteReportRater rater;
        try {
            rater = DefaultRatingLoader.getServerReportRater("en");
            ScoreReport scoreReport = rater.getScoreReport(report.getResultMap());
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
                                            rater.getRecommendations()
                                                    .getRecommendation(entry.getKey());
                                    PropertyResultRecommendation resultRecommendation =
                                            recommendation.getPropertyResultRecommendation(
                                                    influencer.getResult());
                                    if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                                        printFullRecommendation(
                                                container,
                                                rater,
                                                recommendation,
                                                influencer,
                                                resultRecommendation);
                                    } else {
                                        printShortRecommendation(
                                                container, influencer, resultRecommendation);
                                    }
                                }
                            });
        } catch (Exception ex) {
            container.add(
                    new TextContainer(
                            "Could not append recommendations - unrelated error", AnsiColor.RED));
            LOGGER.error("Could not append recommendations", ex);
        }
        return container;
    }

    private void printFullRecommendation(
            ListContainer outerContainer,
            SiteReportRater rater,
            Recommendation recommendation,
            PropertyResultRatingInfluencer influencer,
            PropertyResultRecommendation resultRecommendation) {
        AnsiColor color = getColorForRecommendation(influencer);
        outerContainer.add(
                new KeyValueContainer(
                        recommendation.getShortName(),
                        AnsiColor.DEFAULT_COLOR,
                        influencer.getResult().getName(),
                        color));
        int scoreInfluence = 0;
        String additionalInfo = "";
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
        outerContainer.add(
                new KeyValueContainer(
                        "Score", AnsiColor.DEFAULT_COLOR, scoreInfluence + additionalInfo, color));
        if (influencer.hasScoreCap()) {
            outerContainer.add(
                    new KeyValueContainer(
                            "Score cap",
                            AnsiColor.DEFAULT_COLOR,
                            influencer.getScoreCap().toString(),
                            color));
        }
        outerContainer.add(
                new KeyValueContainer(
                        "Information",
                        AnsiColor.DEFAULT_COLOR,
                        resultRecommendation.getShortDescription(),
                        color));
        outerContainer.add(
                new KeyValueContainer(
                        "Recommendation",
                        AnsiColor.DEFAULT_COLOR,
                        resultRecommendation.getHandlingRecommendation(),
                        color));
    }

    private void printShortRecommendation(
            ListContainer outerContainer,
            PropertyResultRatingInfluencer influencer,
            PropertyResultRecommendation resultRecommendation) {
        AnsiColor color = getColorForRecommendation(influencer);
        outerContainer.add(
                new TextContainer(
                        resultRecommendation.getShortDescription()
                                + ". "
                                + resultRecommendation.getHandlingRecommendation(),
                        color));
    }

    public ReportContainer createPerformanceDataContainer(ServerReport report) {
        ListContainer container = new ListContainer();
        if (detail.isGreaterEqualTo(ScannerDetail.ALL)) {
            container.add(new HeadlineContainer("Scanner Performance"));
            try {
                container.add(
                        createDefaultKeyValueContainer(
                                "TCP connections",
                                String.valueOf(report.getPerformedConnections())));
                ListContainer performance = new ListContainer(1);
                container.add(performance);
                performance.add(new HeadlineContainer("Probe execution performance"));
                for (PerformanceData data : report.getProbePerformanceData()) {
                    Period period = new Period(data.getStopTime() - data.getStartTime());
                    performance.add(
                            createDefaultKeyValueContainer(
                                    data.getType().getName(),
                                    PeriodFormat.getDefault().print(period)));
                }
            } catch (Exception e) {
                container.add(createDefaultTextContainer("Error: " + e.getMessage()));
            }
        } else {
            LOGGER.debug("Not printing performance data.");
        }
        return container;
    }
}
