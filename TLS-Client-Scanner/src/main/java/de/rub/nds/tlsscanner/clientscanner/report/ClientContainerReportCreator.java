/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.report;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.probe.result.IntegerResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.scanner.core.report.PerformanceData;
import de.rub.nds.scanner.core.report.PrintingScheme;
import de.rub.nds.scanner.core.report.container.HeadlineContainer;
import de.rub.nds.scanner.core.report.container.KeyValueContainer;
import de.rub.nds.scanner.core.report.container.ListContainer;
import de.rub.nds.scanner.core.report.container.ReportContainer;
import de.rub.nds.scanner.core.report.container.TableContainer;
import de.rub.nds.scanner.core.report.container.TextContainer;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.core.probe.padding.PaddingOracleStrength;
import de.rub.nds.tlsscanner.core.report.DefaultPrintingScheme;
import de.rub.nds.tlsscanner.core.report.TlsReportCreator;
import de.rub.nds.tlsscanner.core.util.CollectionUtils;
import de.rub.nds.tlsscanner.core.vector.response.EqualityError;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.core.vector.statistics.ResponseCounter;
import de.rub.nds.tlsscanner.core.vector.statistics.VectorContainer;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.joda.time.Period;
import org.joda.time.format.PeriodFormat;

/** TODO: Need to be completed. */
public class ClientContainerReportCreator extends TlsReportCreator<ClientReport> {

    public ClientContainerReportCreator(ScannerDetail detail) {
        super(detail, DefaultPrintingScheme.getDefaultPrintingScheme());
    }

    public ClientContainerReportCreator(ScannerDetail detail, PrintingScheme scheme) {
        super(detail, scheme);
    }

    public ReportContainer createReport(ClientReport report) {
        ListContainer rootContainer = new ListContainer();
        rootContainer.add(createProtocolVersionContainer(report));
        rootContainer.add(createCipherSuiteContainer(report));
        rootContainer.add(createCompressionContainer(report));
        rootContainer.add(createExtensionsContainer(report));
        rootContainer.add(createNamedGroupsContainer(report));
        rootContainer.add(createKeySharesContainer(report));
        rootContainer.add(createSupportedNamedGroupsContainer(report));
        rootContainer.add(createSignatureAndHashAlgorithmsContainer(report));
        rootContainer.add(createAdvertisedPointFormatsContainer(report));
        rootContainer.add(createSupportedPointFormatsContainer(report));
        rootContainer.add(createRecordFragmentationContainer(report));
        rootContainer.add(createAlpnContainer(report));
        rootContainer.add(createAttackVulnerabilitiesContainer(report));
        rootContainer.add(createAlpacaContainer(report));
        rootContainer.add(createPaddingOracleContainer(report));
        rootContainer.add(createSessionResumptionContainer(report));
        rootContainer.add(createDheParameterContainer(report));
        rootContainer.add(createClientAuthenticationContainer(report));
        rootContainer.add(createServerCertificateKeySizeContainer(report));
        rootContainer.add(createCertificateContainer(report));
        rootContainer.add(createQuirksContainer(report));
        if (report.getProtocolType() == ProtocolType.DTLS) {
            rootContainer.add(createDtlsReorderingContainer(report));
            rootContainer.add(createDtlsFragmenatationContainer(report));
            rootContainer.add(createDtlsCookieContainer(report));
            rootContainer.add(createDtlsMessageSequenceNumberContainer(report));
            rootContainer.add(createDtlsRetransmissionsContainer(report));
            rootContainer.add(createDtlsBugsContainer(report));
        }
        rootContainer.add(createProbePerformanceContainer(report));
        return rootContainer;
    }

    protected ReportContainer createDtlsCookieContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("DTLS Hello Verify Request"));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.ACCEPTS_HVR_LEGACY_SERVER_VERSION_MISMATCH, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.ACCEPTS_HVR_RECORD_SEQUENCE_NUMBER_MISMATCH, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.ACCEPTS_SERVER_HELLO_RECORD_SEQUENCE_NUMBER_MISMATCH,
                        report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.HAS_CLIENT_HELLO_MISMATCH, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE, report));
        return container;
    }

    protected ReportContainer createSupportedPointFormatsContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Supported Point Formats"));
        container.add(
                createDefaultKeyValueContainer(
                        "Uncompressed",
                        printingScheme.getEncodedValueText(
                                report, TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT)));
        container.add(
                createDefaultKeyValueContainer(
                        "ANSI X9.62 Compressed Prime",
                        printingScheme.getEncodedValueText(
                                report, TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME)));
        container.add(
                createDefaultKeyValueContainer(
                        "ANSI X9.62 Compressed Char2",
                        printingScheme.getEncodedValueText(
                                report, TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2)));
        container.add(
                createDefaultKeyValueContainer(
                        "Accepts Undefined Format",
                        printingScheme.getEncodedValueText(
                                report,
                                TlsAnalyzedProperty.HANDSHAKES_WITH_UNDEFINED_POINT_FORMAT)));
        return container;
    }

    protected ReportContainer createServerCertificateKeySizeContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Expected Server Certificate Public Key Size"));
        container.add(
                createDefaultKeyValueContainer(
                        "RSA Key Size Enforced",
                        printingScheme.getEncodedValueText(
                                report,
                                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA)));
        container.add(
                createDefaultKeyValueContainer(
                        "RSA Sig. Key Size Enforced",
                        printingScheme.getEncodedValueText(
                                report,
                                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA_SIG)));
        container.add(
                createDefaultKeyValueContainer(
                        "DSS Key Size Enforced",
                        printingScheme.getEncodedValueText(
                                report,
                                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DSS)));
        container.add(
                createDefaultKeyValueContainer(
                        "DH Key Size Enforced",
                        printingScheme.getEncodedValueText(
                                report, TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DH)));

        if (report.getResult(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA)
                == TestResults.TRUE) {
            container.add(
                    new KeyValueContainer(
                            "Min. RSA Modulus Accepted",
                            AnsiColor.DEFAULT_COLOR,
                            report.getIntegerResult(
                                            TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA)
                                    .getValue()
                                    .toString(),
                            AnsiColor.DEFAULT_COLOR));
        }

        if (report.getResult(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA_SIG)
                == TestResults.TRUE) {
            container.add(
                    new KeyValueContainer(
                            "Min. RSA Sig. Modulus Accepted",
                            AnsiColor.DEFAULT_COLOR,
                            report.getIntegerResult(
                                            TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA_SIG)
                                    .getValue()
                                    .toString(),
                            AnsiColor.DEFAULT_COLOR));
        }

        if (report.getResult(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DSS)
                == TestResults.TRUE) {
            container.add(
                    new KeyValueContainer(
                            "Min. DSS Modulus Accepted",
                            AnsiColor.DEFAULT_COLOR,
                            report.getIntegerResult(
                                            TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DSS)
                                    .getValue()
                                    .toString(),
                            AnsiColor.DEFAULT_COLOR));
        }

        if (report.getResult(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DH)
                == TestResults.TRUE) {
            container.add(
                    new KeyValueContainer(
                            "Min. DH Modulus Accepted",
                            AnsiColor.DEFAULT_COLOR,
                            report.getIntegerResult(TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DH)
                                    .getValue()
                                    .toString(),
                            AnsiColor.DEFAULT_COLOR));
        }
        return container;
    }

    @Override
    protected ReportContainer createCipherSuiteContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        container.add(createSupportedCipherSuitesContainer(report));
        container.add(createSupportedCipherSuitesByVersionContainer(report));
        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            container.add(createSupportedSymmetricAlgorithmsContainer(report));
            container.add(createSupportedKeyExchangeAlgorithmsContainer(report));
            container.add(createSupportedKeyExchangeSignaturesContainer(report));
            container.add(createSupportedCipherTypesContainer(report));
        }
        container.add(createPerfectForwardSecrecyContainer(report));
        return container;
    }

    @Override
    protected ListContainer createSupportedCipherSuitesContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Supported Cipher Suites"));
        TableContainer table = new TableContainer();
        container.add(table);
        table.setHeadlineList(getCipherSuitesTableHeadlines());
        for (CipherSuite suite :
                CollectionUtils.mergeCollectionsIntoSet(
                        getRealClientAdvertisedCipherSuites(report),
                        report.getSupportedCipherSuites())) {
            List<TextContainer> currentTableRow = new LinkedList<>();
            currentTableRow.add(new TextContainer(suite.name(), getColorForCipherSuite(suite)));
            if (report.getClientAdvertisedCipherSuites().contains(suite)) {
                currentTableRow.add(createDefaultTextContainer("x"));
            } else {
                currentTableRow.add(createDefaultTextContainer("-"));
            }
            if (report.getSupportedCipherSuites().contains(suite)) {
                currentTableRow.add(createDefaultTextContainer("x"));
            } else {
                currentTableRow.add(createDefaultTextContainer("-"));
            }
            table.addLineToTable(currentTableRow);
        }
        return container;
    }

    private static List<TextContainer> getCipherSuitesTableHeadlines() {
        List<TextContainer> container = new LinkedList<>();
        container.add(new TextContainer("Cipher Suite", AnsiColor.BOLD));
        container.add(new TextContainer("Advertised", AnsiColor.BOLD));
        container.add(new TextContainer("Negotiated", AnsiColor.BOLD));
        return container;
    }

    private List<CipherSuite> getRealClientAdvertisedCipherSuites(ClientReport report) {
        return report.getClientAdvertisedCipherSuites().stream()
                .filter(suite -> suite.isRealCipherSuite())
                .collect(Collectors.toList());
    }

    private ReportContainer createExtensionsContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        if (report.getClientAdvertisedExtensions() != null) {
            container.add(new HeadlineContainer("Advertised Extensions"));
            ListContainer listContainer = new ListContainer();
            for (ExtensionType type : report.getClientAdvertisedExtensions()) {
                listContainer.add(createDefaultTextContainer(type.name()));
            }
            container.add(listContainer);
        }
        return container;
    }

    private ReportContainer createSignatureAndHashAlgorithmsContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        if (report.getClientAdvertisedSignatureAndHashAlgorithms() != null) {
            container.add(new HeadlineContainer("Advertised Signature and Hash Algorithms"));
            ListContainer listContainer = new ListContainer();
            for (SignatureAndHashAlgorithm algo :
                    report.getClientAdvertisedSignatureAndHashAlgorithms()) {
                listContainer.add(createDefaultTextContainer(algo.name()));
            }
            container.add(listContainer);
        }
        return container;
    }

    private ReportContainer createNamedGroupsContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        if (report.getClientAdvertisedNamedGroupsList() != null) {
            container.add(new HeadlineContainer("Advertised Named Groups"));
            ListContainer listContainer = new ListContainer();
            for (NamedGroup group : report.getClientAdvertisedNamedGroupsList()) {
                listContainer.add(createDefaultTextContainer(group.name()));
            }
            container.add(listContainer);
        }
        return container;
    }

    private ReportContainer createSupportedNamedGroupsContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        if (report.getResult(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS) != null
                && report.getResult(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS)
                        != TestResults.UNASSIGNED_ERROR) {
            container.add(new HeadlineContainer("Supported Named Groups"));
            ListContainer listContainer = new ListContainer();
            for (NamedGroup group :
                    (List<NamedGroup>)
                            report.getListResult(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS)
                                    .getList()) {
                listContainer.add(createDefaultTextContainer(group.name()));
            }
            container.add(listContainer);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS) != null
                && report.getResult(TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS)
                        != TestResults.UNASSIGNED_ERROR) {
            container.add(new HeadlineContainer("Supported Named Groups (TLS 1.3)"));
            ListContainer listContainer = new ListContainer();
            for (NamedGroup group :
                    (List<NamedGroup>)
                            report.getListResult(TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS)
                                    .getList()) {
                listContainer.add(createDefaultTextContainer(group.name()));
            }
            container.add(listContainer);
        }
        return container;
    }

    private ReportContainer createKeySharesContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        if (report.getClientAdvertisedKeyShareNamedGroupsList() != null) {
            container.add(new HeadlineContainer("Advertised Key Shares"));
            ListContainer listContainer = new ListContainer();
            for (NamedGroup group : report.getClientAdvertisedKeyShareNamedGroupsList()) {
                listContainer.add(createDefaultTextContainer(group.name()));
            }
            container.add(listContainer);
        }
        return container;
    }

    private ReportContainer createAdvertisedPointFormatsContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        if (report.getClientAdvertisedPointFormatsList() != null) {
            container.add(new HeadlineContainer("Advertised Elliptic Curve Point Formats"));
            ListContainer listContainer = new ListContainer();
            for (ECPointFormat format : report.getClientAdvertisedPointFormatsList()) {
                listContainer.add(createDefaultTextContainer(format.name()));
            }
            container.add(listContainer);
        }
        return container;
    }

    private ReportContainer createSessionResumptionContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        if (report.getExecutedProbes().contains(TlsProbeType.RESUMPTION)) {
            container.add(new HeadlineContainer("Session Resumption"));
            container.add(
                    createKeyValueContainer(
                            TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION, report));
            if (report.getProtocolType() == ProtocolType.DTLS) {
                container.add(
                        createKeyValueContainer(
                                TlsAnalyzedProperty
                                        .SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION,
                                report));
            }
            container.add(
                    createKeyValueContainer(
                            TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION, report));
            if (report.getProtocolType() == ProtocolType.DTLS) {
                container.add(
                        createKeyValueContainer(
                                TlsAnalyzedProperty
                                        .SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION,
                                report));
            }
        }
        return container;
    }

    private ReportContainer createAttackVulnerabilitiesContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Attack Vulnerabilities"));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE, report));
        if (report.getKnownPaddingOracleVulnerability() != null) {
            container.add(
                    new TextContainer(
                            "- " + report.getKnownPaddingOracleVulnerability().getShortName(),
                            AnsiColor.RED));
        }
        container.add(createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_FREAK, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_FREAK_DOWNGRADE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_LOGJAM, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.ALPACA_MITIGATED, report));
        return container;
    }

    private ReportContainer createDheParameterContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("DHE Parameters"));
        IntegerResult lowestPossibleDheModulusSize =
                report.getIntegerResult(TlsAnalyzedProperty.LOWEST_POSSIBLE_DHE_MODULUS_SIZE);
        if (lowestPossibleDheModulusSize != null) {
            String containerKey = "Lowest accepted modulus (>= 2 bits)";
            String containerValue = lowestPossibleDheModulusSize + " bits";
            container.add(
                    new KeyValueContainer(
                            containerKey,
                            AnsiColor.DEFAULT_COLOR,
                            containerValue,
                            getColorForDhModulusSize(lowestPossibleDheModulusSize.getValue())));
        }
        IntegerResult highestPossibleDheModulusSize =
                report.getIntegerResult(TlsAnalyzedProperty.HIGHEST_POSSIBLE_DHE_MODULUS_SIZE);
        if (highestPossibleDheModulusSize != null) {
            String containerKey = "Highest accepted modulus (<= 8192 bits)";
            String containerValue = highestPossibleDheModulusSize + " bits";
            container.add(
                    new KeyValueContainer(
                            containerKey,
                            AnsiColor.DEFAULT_COLOR,
                            containerValue,
                            getColorForDhModulusSize(highestPossibleDheModulusSize.getValue())));
        }
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_EVEN_MODULUS, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_MOD3_MODULUS, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_MODULUS_ONE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_GENERATOR_ONE, report));
        return container;
    }

    private ReportContainer createQuirksContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Quirk Evaluation"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.REQUIRES_SNI, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.FORCED_COMPRESSION, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.TLS_1_3_DOWNGRADE_PROTECTION, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.SENDS_APPLICATION_MESSAGE, report));
        return container;
    }

    private ReportContainer createClientAuthenticationContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Client authentication"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_CCA, report));
        return container;
    }

    private ReportContainer createAlpnContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        if (report.getExecutedProbes().contains(TlsProbeType.ALPN)
                && report.getClientAdvertisedAlpns() != null) {
            container.add(new HeadlineContainer("Advertised ALPNs"));
            ListContainer listContainer = new ListContainer();
            for (String protocol : report.getClientAdvertisedAlpns()) {
                listContainer.add(createDefaultTextContainer(protocol));
            }
            container.add(listContainer);
        }
        return container;
    }

    private ReportContainer createPaddingOracleContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        if (Objects.equals(
                report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE),
                TestResults.TRUE)) {
            container.add(
                    createPaddingOracleKnownVulnerabilityContainer(
                            report.getKnownPaddingOracleVulnerability()));
        }
        if (report.getPaddingOracleTestResultList() == null
                || report.getPaddingOracleTestResultList().isEmpty()) {
            container.add(new HeadlineContainer("Padding Oracle Response Map"));
            container.add(createDefaultTextContainer("No test results"));
        } else {
            List<InformationLeakTest> informationLeakTestList =
                    new LinkedList<>(report.getPaddingOracleTestResultList());
            appendInformationLeakTestList(
                    container, informationLeakTestList, "Padding Oracle Response Map");
        }
        return container;
    }

    private ListContainer createPaddingOracleKnownVulnerabilityContainer(
            KnownPaddingOracleVulnerability knownVulnerability) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Padding Oracle Identification"));
        if (knownVulnerability == null) {
            container.add(
                    new KeyValueContainer(
                            "Identification",
                            AnsiColor.DEFAULT_COLOR,
                            "Could not identify vulnerability. Please contact us if you know which software/hardware is generating this behavior.",
                            AnsiColor.YELLOW));
            return container;
        }
        container.add(
                new KeyValueContainer(
                        "Identification",
                        AnsiColor.DEFAULT_COLOR,
                        knownVulnerability.getLongName(),
                        AnsiColor.RED));
        container.add(
                new KeyValueContainer(
                        "CVE",
                        AnsiColor.DEFAULT_COLOR,
                        knownVulnerability.getCve(),
                        AnsiColor.RED));
        AnsiColor oracleStrengthColor =
                knownVulnerability.getStrength() != PaddingOracleStrength.WEAK
                        ? AnsiColor.RED
                        : AnsiColor.YELLOW;
        container.add(
                new KeyValueContainer(
                        "Strength",
                        AnsiColor.DEFAULT_COLOR,
                        knownVulnerability.getStrength().name(),
                        oracleStrengthColor));
        AnsiColor oracleObservableColor =
                knownVulnerability.isObservable() ? AnsiColor.RED : AnsiColor.YELLOW;
        container.add(
                new KeyValueContainer(
                        "Observable",
                        AnsiColor.DEFAULT_COLOR,
                        String.valueOf(knownVulnerability.isObservable()),
                        oracleObservableColor));
        container.add(new HeadlineContainer("Vulnerability Description"));
        container.add(createDefaultTextContainer(knownVulnerability.getDescription()));
        container.add(new HeadlineContainer("Affected Products"));
        for (String products : knownVulnerability.getAffectedProducts()) {
            container.add(new TextContainer(products, AnsiColor.YELLOW));
        }
        container.add(
                createDefaultTextContainer(
                        "If your tested software/hardware is not in this list, please let us know so we can add it here."));

        return container;
    }

    private void appendInformationLeakTestList(
            ListContainer outerContainer,
            List<InformationLeakTest> informationLeakTestList,
            String title) {
        outerContainer.add(new HeadlineContainer(title));
        ListContainer container = new ListContainer(1);
        outerContainer.add(container);
        container.add(new HeadlineContainer("Response Map"));
        TableContainer tableContainer = new TableContainer();
        container.add(tableContainer);
        // Table headlines
        LinkedList<TextContainer> headline =
                informationLeakTestList.get(0).getTestInfo().getFieldNames().stream()
                        .map(this::createDefaultTextContainer)
                        .collect(Collectors.toCollection(LinkedList::new));
        headline.add(createDefaultTextContainer("Behavior"));
        headline.add(createDefaultTextContainer("Vulnerable"));
        headline.add(createDefaultTextContainer("P value"));
        tableContainer.setHeadlineList(headline);

        for (InformationLeakTest testResult : informationLeakTestList) {
            String valueP =
                    testResult.getValueP() >= 0.001
                            ? String.format("%.3f", testResult.getValueP())
                            : "<0.001";
            List<String> resultStrings =
                    Arrays.asList(testResult.getTestInfo().getTechnicalName().split(":"));
            if (testResult.getValueP() < 0.01) {
                List<TextContainer> tableLine =
                        resultStrings.stream()
                                .map(x -> new TextContainer(x, AnsiColor.RED))
                                .collect(Collectors.toCollection(LinkedList::new));
                tableLine.add(
                        new TextContainer(testResult.getEqualityError().name(), AnsiColor.RED));
                tableLine.add(new TextContainer("VULNERABLE", AnsiColor.RED));
                tableLine.add(new TextContainer(valueP, AnsiColor.RED));
                tableContainer.addLineToTable(tableLine);
            } else if (testResult.getValueP() < 0.05) {
                List<TextContainer> tableLine =
                        resultStrings.stream()
                                .map(x -> new TextContainer(x, AnsiColor.YELLOW))
                                .collect(Collectors.toCollection(LinkedList::new));
                tableLine.add(
                        new TextContainer(testResult.getEqualityError().name(), AnsiColor.YELLOW));
                tableLine.add(new TextContainer("PROBABLY VULNERABLE", AnsiColor.YELLOW));
                tableLine.add(new TextContainer(valueP, AnsiColor.YELLOW));
                tableContainer.addLineToTable(tableLine);
            } else if (testResult.getValueP() < 1) {
                List<TextContainer> tableLine =
                        resultStrings.stream()
                                .map(x -> new TextContainer(x, AnsiColor.GREEN))
                                .collect(Collectors.toCollection(LinkedList::new));
                tableLine.add(new TextContainer("No significant difference", AnsiColor.GREEN));
                tableLine.add(new TextContainer("NOT VULNERABLE", AnsiColor.GREEN));
                tableLine.add(new TextContainer(valueP, AnsiColor.GREEN));
                tableContainer.addLineToTable(tableLine);
            } else {
                List<TextContainer> tableLine =
                        resultStrings.stream()
                                .map(x -> new TextContainer(x, AnsiColor.GREEN))
                                .collect(Collectors.toCollection(LinkedList::new));
                tableLine.add(new TextContainer("No behavior difference", AnsiColor.GREEN));
                tableLine.add(new TextContainer("NOT VULNERABLE", AnsiColor.GREEN));
                tableLine.add(new TextContainer(valueP, AnsiColor.GREEN));
                tableContainer.addLineToTable(tableLine);
            }
            if ((detail == ScannerDetail.DETAILED
                            && Objects.equals(
                                    testResult.isSignificantDistinctAnswers(), Boolean.TRUE))
                    || detail == ScannerDetail.ALL) {
                if (testResult.getEqualityError() != EqualityError.NONE
                        || detail == ScannerDetail.ALL) {
                    appendInformationLeakTestResult(testResult, container);
                }
            }
        }
    }

    private void appendInformationLeakTestResult(
            InformationLeakTest informationLeakTest, ListContainer outerContainer) {
        ListContainer container = new ListContainer(1);
        container.add(new HeadlineContainer(informationLeakTest.getTestInfo().getPrintableName()));
        outerContainer.add(container);
        ResponseFingerprint defaultAnswer =
                informationLeakTest.retrieveMostCommonAnswer().getFingerprint();
        List<VectorContainer> vectorContainerList = informationLeakTest.getVectorContainerList();
        for (VectorContainer vectorContainer : vectorContainerList) {
            ListContainer vectorResult = new ListContainer(1);
            container.add(vectorResult);
            vectorResult.add(new HeadlineContainer(vectorContainer.getVector().getName()));
            TableContainer responseTable = new TableContainer();
            vectorResult.add(responseTable);
            responseTable.setHeadlineList(
                    List.of(
                            new TextContainer("Fingerprint", AnsiColor.DEFAULT_COLOR),
                            new TextContainer("Received (Total)", AnsiColor.DEFAULT_COLOR),
                            new TextContainer("Received (Percentage)", AnsiColor.DEFAULT_COLOR)));
            for (ResponseCounter counter : vectorContainer.getDistinctResponsesCounterList()) {
                AnsiColor color =
                        counter.getFingerprint().equals(defaultAnswer)
                                ? AnsiColor.GREEN
                                : AnsiColor.RED;
                List<TextContainer> tableLine = new LinkedList<>();
                responseTable.addLineToTable(tableLine);
                tableLine.add(new TextContainer(counter.getFingerprint().toHumanReadable(), color));
                tableLine.add(new TextContainer(String.valueOf(counter.getCounter()), color));
                tableLine.add(
                        new TextContainer(
                                String.format("%.2f", counter.getProbability() * 100) + "%",
                                color));
            }
        }
    }

    private ReportContainer createProbePerformanceContainer(ClientReport report) {
        ListContainer container = new ListContainer();
        if (detail.isGreaterEqualTo(ScannerDetail.ALL)) {
            container.add(new HeadlineContainer("Scanner Performance"));
            try {
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
        }
        return container;
    }
}
