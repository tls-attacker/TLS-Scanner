/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.report;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.scanner.core.report.PrintingScheme;
import de.rub.nds.scanner.core.report.ReportCreator;
import de.rub.nds.scanner.core.report.container.HeadlineContainer;
import de.rub.nds.scanner.core.report.container.KeyValueContainer;
import de.rub.nds.scanner.core.report.container.ListContainer;
import de.rub.nds.scanner.core.report.container.ReportContainer;
import de.rub.nds.scanner.core.report.container.TextContainer;
import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateIssue;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class TlsReportCreator<ReportT extends TlsScanReport> extends ReportCreator<ReportT> {

    public TlsReportCreator(ScannerDetail detail, PrintingScheme scheme) {
        super(detail, scheme);
    }

    protected ReportContainer createProtocolVersionContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Supported Protocol Versions"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_SSL_2, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_SSL_3, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_DTLS_1_3, report));
        return container;
    }

    protected ReportContainer createCompressionContainer(ReportT report) {
        ListContainer container = new ListContainer();
        if (report.getSupportedCompressionMethods() != null) {
            container.add(new HeadlineContainer("Supported Compressions"));
            for (CompressionMethod compression : report.getSupportedCompressionMethods()) {
                container.add(
                        new TextContainer(compression.name(), getColorForCompression(compression)));
            }
        }
        return container;
    }

    protected ReportContainer createCipherSuiteContainer(ReportT report) {
        ListContainer cipherSuiteContainer = new ListContainer();
        cipherSuiteContainer.add(createSupportedCipherSuitesContainer(report));
        cipherSuiteContainer.add(createSupportedCipherSuitesByVersionContainer(report));
        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            cipherSuiteContainer.add(createSupportedSymmetricAlgorithmsContainer(report));
            cipherSuiteContainer.add(createSupportedKeyExchangeAlgorithmsContainer(report));
            cipherSuiteContainer.add(createSupportedKeyExchangeSignaturesContainer(report));
            cipherSuiteContainer.add(createSupportedCipherTypesContainer(report));
        }
        cipherSuiteContainer.add(createPerfectForwardSecrecyContainer(report));
        return cipherSuiteContainer;
    }

    protected ListContainer createSupportedCipherSuitesContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Supported Cipher Suites"));
        for (CipherSuite suite : report.getSupportedCipherSuites()) {
            container.add(new TextContainer(suite.name(), getColorForCipherSuite(suite)));
        }
        return container;
    }

    protected ListContainer createSupportedCipherSuitesByVersionContainer(ReportT report) {
        ListContainer container = new ListContainer();
        if (report.getVersionSuitePairs() != null) {
            for (VersionSuiteListPair pair : report.getVersionSuitePairs()) {
                String enforcesCsOrderingSuffix =
                        report.getResult(TlsAnalyzedProperty.ENFORCES_CS_ORDERING)
                                        == TestResults.TRUE
                                ? "(server order)"
                                : "";
                String versionHeadline =
                        "Supported in "
                                + pair.getVersion().toHumanReadable()
                                + enforcesCsOrderingSuffix;
                container.add(new HeadlineContainer(versionHeadline));

                ListContainer versionSuites = new ListContainer();
                for (CipherSuite suite : pair.getCipherSuiteList()) {
                    versionSuites.add(
                            new TextContainer(suite.name(), getColorForCipherSuite(suite)));
                }
                container.add(versionSuites);
            }
        }
        return container;
    }

    protected ListContainer createSupportedSymmetricAlgorithmsContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Symmetric Supported"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_EXPORT, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_ANON, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_DES, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_SEED, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_IDEA, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_RC2, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_RC4, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_3DES, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_AES, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_CAMELLIA, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_ARIA, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_CHACHA, report));
        return container;
    }

    protected ListContainer createSupportedKeyExchangeAlgorithmsContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Key Exchange Supported"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_RSA, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_STATIC_DH, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_DHE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_ECDHE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_GOST, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_KERBEROS, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_PSK_RSA, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_PSK_DHE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_FORTEZZA, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_NEWHOPE, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_ECMQV, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE, report));
        return container;
    }

    protected ListContainer createSupportedKeyExchangeSignaturesContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Key Exchange Signatures"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_RSA_CERT, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_ECDSA, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_DSS, report));
        return container;
    }

    protected ListContainer createSupportedCipherTypesContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Cipher Types Supports"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_AEAD, report));
        return container;
    }

    protected ListContainer createPerfectForwardSecrecyContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Perfect Forward Secrecy"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_PFS, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.PREFERS_PFS, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_ONLY_PFS, report));
        return container;
    }

    protected ReportContainer createRecordFragmentationContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Record Fragmentation"));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION, report));
        return container;
    }

    protected ReportContainer createDtlsFragmenatationContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("DTLS Fragmentation"));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS,
                        report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty
                                .DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION,
                        report));
        return container;
    }

    protected ReportContainer createDtlsRetransmissionsContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("DTLS Retransmissions"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SENDS_RETRANSMISSIONS, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS, report));
        container.add(
                createDefaultKeyValueContainer(
                        "Total retransmissions received",
                        report.getTotalReceivedRetransmissions().toString()));
        return container;
    }

    protected ReportContainer createDtlsBugsContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("DTLS [EXPERIMENTAL]"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.HAS_EARLY_FINISHED_BUG, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_FINISHED, report));
        container.add(
                createKeyValueContainer(TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_APP_DATA, report));
        return container;
    }

    protected ReportContainer createDtlsMessageSequenceNumberContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("DTLS Message Sequence Number"));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE, report));
        container.add(
                createKeyValueContainer(
                        TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, report));
        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            container.add(
                    createKeyValueContainer(
                            TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE, report));
            container.add(
                    createKeyValueContainer(
                            TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE,
                            report));
            container.add(
                    createKeyValueContainer(
                            TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, report));
        }
        return container;
    }

    protected ReportContainer createDtlsReorderingContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("DTLS Reordering"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_REORDERING, report));
        return container;
    }

    protected ReportContainer createAlpacaContainer(ReportT report) {
        ListContainer container = new ListContainer();
        container.add(new HeadlineContainer("Alpaca Details"));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.STRICT_ALPN, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.STRICT_SNI, report));
        container.add(createKeyValueContainer(TlsAnalyzedProperty.ALPACA_MITIGATED, report));
        return container;
    }

    protected ReportContainer createCertificateContainer(ReportT report) {
        ListContainer container = new ListContainer();
        int certCtr = 1;
        if (report.getCertificateChainList() != null
                && !report.getCertificateChainList().isEmpty()) {
            for (CertificateChainReport chain : report.getCertificateChainList()) {
                container.add(
                        new HeadlineContainer(
                                "Certificate Chain (Certificate "
                                        + certCtr
                                        + " of "
                                        + report.getCertificateChainList().size()
                                        + ")"));
                appendCertificate(container, chain);
                certCtr++;
            }
        }
        return container;
    }

    private void appendCertificate(ListContainer outerContainer, CertificateChainReport chain) {
        ListContainer container = new ListContainer();
        container.add(
                new KeyValueContainer(
                        "Chain ordered",
                        AnsiColor.DEFAULT_COLOR,
                        String.valueOf(chain.getChainIsOrdered()),
                        chain.getChainIsOrdered() ? AnsiColor.GREEN : AnsiColor.YELLOW));
        container.add(
                new KeyValueContainer(
                        "Contains Trust Anchor",
                        AnsiColor.DEFAULT_COLOR,
                        String.valueOf(chain.getContainsTrustAnchor()),
                        chain.getContainsTrustAnchor() ? AnsiColor.RED : AnsiColor.GREEN));
        container.add(
                new KeyValueContainer(
                        "Generally Trusted",
                        AnsiColor.DEFAULT_COLOR,
                        String.valueOf(chain.getGenerallyTrusted()),
                        chain.getGenerallyTrusted() ? AnsiColor.GREEN : AnsiColor.RED));
        if (chain.getCertificateIssues().size() > 0) {
            ListContainer issuesContainer = new ListContainer(1);
            issuesContainer.add(new HeadlineContainer("Certificate Issues"));
            for (CertificateIssue issue : chain.getCertificateIssues()) {
                issuesContainer.add(new TextContainer(issue.getHumanReadable(), AnsiColor.RED));
            }
            container.add(issuesContainer);
        }
        if (!chain.getCertificateReportList().isEmpty()) {
            for (int i = 0; i < chain.getCertificateReportList().size(); i++) {
                CertificateReport certReport = chain.getCertificateReportList().get(i);
                ListContainer subCertificateContainer = new ListContainer(1);
                subCertificateContainer.add(new HeadlineContainer("Certificate #" + (i + 1)));
                if (certReport.getSubject() != null) {
                    subCertificateContainer.add(
                            createDefaultKeyValueContainer("Subject", certReport.getSubject()));
                }

                if (certReport.getIssuer() != null) {
                    subCertificateContainer.add(
                            createDefaultKeyValueContainer("Issuer", certReport.getIssuer()));
                }
                if (certReport.getNotBefore() != null) {
                    if (certReport.getNotBefore().isBeforeNow()) {
                        subCertificateContainer.add(
                                new KeyValueContainer(
                                        "Valid From",
                                        AnsiColor.DEFAULT_COLOR,
                                        certReport.getNotBefore().toString(),
                                        AnsiColor.GREEN));
                    } else {
                        subCertificateContainer.add(
                                new KeyValueContainer(
                                        "Valid From",
                                        AnsiColor.DEFAULT_COLOR,
                                        certReport.getNotBefore().toString() + " - NOT YET VALID",
                                        AnsiColor.RED));
                    }
                }
                if (certReport.getNotAfter() != null) {
                    if (certReport.getNotAfter().isBeforeNow()) {
                        subCertificateContainer.add(
                                new KeyValueContainer(
                                        "Valid Till",
                                        AnsiColor.DEFAULT_COLOR,
                                        certReport.getNotAfter().toString(),
                                        AnsiColor.GREEN));
                    } else {
                        subCertificateContainer.add(
                                new KeyValueContainer(
                                        "Valid Till",
                                        AnsiColor.DEFAULT_COLOR,
                                        certReport.getNotAfter().toString() + " - EXPIRED",
                                        AnsiColor.RED));
                    }
                }
                if (certReport.getNotBefore() != null
                        && certReport.getNotAfter() != null
                        && certReport.getNotAfter().isAfterNow()) {
                    // number of days the certificate is still valid
                    long days =
                            TimeUnit.MILLISECONDS.toDays(
                                    certReport.getNotAfter().toDate().getTime()
                                            - new Date().getTime());
                    if (days < 1) {
                        subCertificateContainer.add(
                                new TextContainer(
                                        "Expires in <1 day! This certificate expires very soon",
                                        AnsiColor.RED));
                    } else if (days < 3) {
                        subCertificateContainer.add(
                                new TextContainer(
                                        "Expires in "
                                                + days
                                                + " days! This certificate expires very soon",
                                        AnsiColor.RED));
                    } else if (days < 14) {
                        subCertificateContainer.add(
                                new TextContainer(
                                        "Expires in "
                                                + days
                                                + " days! This certificate expires soon",
                                        AnsiColor.YELLOW));
                    } else if (days < 31) {
                        subCertificateContainer.add(
                                new TextContainer(
                                        "Expires in " + days + " days.", AnsiColor.DEFAULT_COLOR));
                    } else if (days < 730) {
                        subCertificateContainer.add(
                                new TextContainer(
                                        "Expires in " + days + " days.", AnsiColor.GREEN));
                    } else if (Objects.equals(certReport.getLeafCertificate(), Boolean.TRUE)) {
                        subCertificateContainer.add(
                                new TextContainer(
                                        "Expires in "
                                                + days
                                                + " days. This is usually too long for a leaf certificate",
                                        AnsiColor.RED));
                    } else {
                        subCertificateContainer.add(
                                new TextContainer(
                                        "Expires in " + days / 365 + " years.", AnsiColor.GREEN));
                    }
                }
                if (certReport.getPublicKey() != null) {
                    appendPublicKey(subCertificateContainer, certReport.getPublicKey());
                }
                if (certReport.getWeakDebianKey() != null) {
                    subCertificateContainer.add(
                            new KeyValueContainer(
                                    "Weak Debian Key",
                                    AnsiColor.DEFAULT_COLOR,
                                    String.valueOf(certReport.getWeakDebianKey()),
                                    certReport.getWeakDebianKey()
                                            ? AnsiColor.RED
                                            : AnsiColor.GREEN));
                }
                if (certReport.getSignatureAlgorithm() != null) {
                    subCertificateContainer.add(
                            createDefaultKeyValueContainer(
                                    "Signature Algorithm",
                                    certReport.getSignatureAlgorithm().getHumanReadable()));
                }
                if (certReport.getHashAlgorithm() != null) {
                    if (certReport.getHashAlgorithm() == HashAlgorithm.SHA1
                            || certReport.getHashAlgorithm() == HashAlgorithm.MD5) {
                        if (!certReport.isTrustAnchor() && !certReport.getSelfSigned()) {
                            subCertificateContainer.add(
                                    new KeyValueContainer(
                                            "Hash Algorithm",
                                            AnsiColor.DEFAULT_COLOR,
                                            certReport.getHashAlgorithm().name(),
                                            AnsiColor.RED));
                        } else {
                            subCertificateContainer.add(
                                    createDefaultKeyValueContainer(
                                            "Hash Algorithm",
                                            certReport.getHashAlgorithm().name()
                                                    + " - Not critical"));
                        }
                    } else {
                        subCertificateContainer.add(
                                new KeyValueContainer(
                                        "Hash Algorithm",
                                        AnsiColor.DEFAULT_COLOR,
                                        certReport.getHashAlgorithm().name(),
                                        AnsiColor.GREEN));
                    }
                }
                if (certReport.getExtendedValidation() != null) {
                    subCertificateContainer.add(
                            new KeyValueContainer(
                                    "Extended Validation",
                                    AnsiColor.DEFAULT_COLOR,
                                    String.valueOf(certReport.getExtendedValidation()),
                                    certReport.getExtendedValidation()
                                            ? AnsiColor.GREEN
                                            : AnsiColor.DEFAULT_COLOR));
                }
                if (certReport.getCertificateTransparency() != null) {
                    subCertificateContainer.add(
                            new KeyValueContainer(
                                    "Certificate Transparency",
                                    AnsiColor.DEFAULT_COLOR,
                                    String.valueOf(certReport.getCertificateTransparency()),
                                    certReport.getCertificateTransparency()
                                            ? AnsiColor.GREEN
                                            : AnsiColor.YELLOW));
                }

                if (certReport.getCrlSupported() != null) {
                    subCertificateContainer.add(
                            new KeyValueContainer(
                                    "CRL Supported",
                                    AnsiColor.DEFAULT_COLOR,
                                    String.valueOf(certReport.getCrlSupported()),
                                    certReport.getCrlSupported()
                                            ? AnsiColor.GREEN
                                            : AnsiColor.DEFAULT_COLOR));
                }
                if (certReport.getOcspSupported() != null) {
                    subCertificateContainer.add(
                            new KeyValueContainer(
                                    "OCSP Supported",
                                    AnsiColor.DEFAULT_COLOR,
                                    String.valueOf(certReport.getOcspSupported()),
                                    certReport.getOcspSupported()
                                            ? AnsiColor.GREEN
                                            : AnsiColor.YELLOW));
                }
                if (certReport.getOcspMustStaple() != null) {
                    subCertificateContainer.add(
                            createDefaultKeyValueContainer(
                                    "OCSP must staple",
                                    String.valueOf(certReport.getOcspMustStaple())));
                }
                if (certReport.getRevoked() != null) {
                    subCertificateContainer.add(
                            new KeyValueContainer(
                                    "RevocationStatus",
                                    AnsiColor.DEFAULT_COLOR,
                                    String.valueOf(certReport.getRevoked()),
                                    certReport.getRevoked() ? AnsiColor.RED : AnsiColor.GREEN));
                }
                if (certReport.getDnsCAA() != null) {
                    subCertificateContainer.add(
                            new KeyValueContainer(
                                    "DNS CCA",
                                    AnsiColor.DEFAULT_COLOR,
                                    String.valueOf(certReport.getDnsCAA()),
                                    certReport.getDnsCAA()
                                            ? AnsiColor.GREEN
                                            : AnsiColor.DEFAULT_COLOR));
                }
                if (certReport.getRocaVulnerable() != null) {
                    subCertificateContainer.add(
                            new KeyValueContainer(
                                    "ROCA (simple)",
                                    AnsiColor.DEFAULT_COLOR,
                                    String.valueOf(certReport.getRocaVulnerable()),
                                    certReport.getRocaVulnerable()
                                            ? AnsiColor.RED
                                            : AnsiColor.GREEN));
                } else {
                    subCertificateContainer.add(
                            createDefaultTextContainer("ROCA (simple) not tested"));
                }
                subCertificateContainer.add(
                        createDefaultKeyValueContainer(
                                "Fingerprint (SHA256)",
                                ArrayConverter.bytesToHexString(
                                        certReport.getSHA256Fingerprint(), false, false)));
                container.add(subCertificateContainer);
            }
        }
        outerContainer.add(container);
    }

    private void appendPublicKey(ListContainer outerContainer, PublicKeyContainer publicKey) {
        if (publicKey instanceof DhPublicKey) {
            DhPublicKey dhPublicKey = (DhPublicKey) publicKey;
            outerContainer.add(
                    createDefaultKeyValueContainer("PublicKey Type:", "Static Diffie Hellman"));

            outerContainer.add(
                    createDefaultKeyHexValueContainer(
                            "Modulus", dhPublicKey.getModulus().toString(16)));
            outerContainer.add(
                    createDefaultKeyHexValueContainer(
                            "Generator", dhPublicKey.getModulus().toString(16)));
            outerContainer.add(
                    createDefaultKeyHexValueContainer(
                            "PublicKey", dhPublicKey.getPublicKey().toString(16)));
        } else if (publicKey instanceof DsaPublicKey) {
            DsaPublicKey dsaPublicKey = (DsaPublicKey) publicKey;
            outerContainer.add(createDefaultKeyValueContainer("PublicKey Type:", "DSA"));
            outerContainer.add(
                    createDefaultKeyHexValueContainer(
                            "Modulus", dsaPublicKey.getModulus().toString(16)));
            outerContainer.add(
                    createDefaultKeyHexValueContainer(
                            "Generator", dsaPublicKey.getGenerator().toString(16)));
            outerContainer.add(
                    createDefaultKeyHexValueContainer("Q", dsaPublicKey.getQ().toString(16)));
            outerContainer.add(
                    createDefaultKeyHexValueContainer("X", dsaPublicKey.getY().toString(16)));
        } else if (publicKey instanceof RsaPublicKey) {
            RsaPublicKey rsaPublicKey = (RsaPublicKey) publicKey;
            outerContainer.add(createDefaultKeyValueContainer("PublicKey Type:", "RSA"));
            outerContainer.add(
                    createDefaultKeyHexValueContainer(
                            "Modulus", rsaPublicKey.getModulus().toString(16)));
            outerContainer.add(
                    createDefaultKeyHexValueContainer(
                            "Public exponent", rsaPublicKey.getPublicExponent().toString(16)));
        } else if (publicKey instanceof EcdhPublicKey) {
            EcdhPublicKey ecPublicKey = (EcdhPublicKey) publicKey;
            outerContainer.add(createDefaultKeyValueContainer("PublicKey Type:", "ECDH"));
            outerContainer.add(
                    createDefaultKeyValueContainer("Group", ecPublicKey.getParameters().getName()));

            outerContainer.add(
                    createDefaultKeyValueContainer(
                            "Public Point", ecPublicKey.getPublicPoint().toString()));
        } else if (publicKey instanceof EcdsaPublicKey) {
            EcdsaPublicKey ecPublicKey = (EcdsaPublicKey) publicKey;
            outerContainer.add(createDefaultKeyValueContainer("PublicKey Type:", "ECDH"));
            outerContainer.add(
                    createDefaultKeyValueContainer("Group", ecPublicKey.getParameters().getName()));
            outerContainer.add(
                    createDefaultKeyValueContainer(
                            "Public Point", ecPublicKey.getPublicPoint().toString()));
        } else {
            outerContainer.add(createDefaultTextContainer(publicKey.toString()));
        }
    }

    protected AnsiColor getColorForCipherSuite(CipherSuite suite) {
        if (suite == null) {
            return AnsiColor.DEFAULT_COLOR;
        }
        CipherSuiteGrade grade = CipherSuiteRater.getGrade(suite);
        switch (grade) {
            case GOOD:
                return AnsiColor.GREEN;
            case LOW:
                return AnsiColor.RED;
            case MEDIUM:
                return AnsiColor.YELLOW;
            case NONE:
                return AnsiColor.DEFAULT_COLOR;
            default:
                return AnsiColor.DEFAULT_COLOR;
        }
    }

    protected AnsiColor getColorForCompression(CompressionMethod compression) {
        if (compression == null) {
            return AnsiColor.DEFAULT_COLOR;
        }
        if (compression == CompressionMethod.NULL) {
            return AnsiColor.GREEN;
        } else {
            return AnsiColor.RED;
        }
    }

    protected AnsiColor getColorForProtocolVersion(ProtocolVersion version) {
        if (version == null) {
            return AnsiColor.DEFAULT_COLOR;
        }
        if (version.name().contains("13") || version.name().contains("12")) {
            return AnsiColor.GREEN;
        } else if (version.name().contains("11") || version.name().contains("10")) {
            return AnsiColor.YELLOW;
        } else if (version.name().contains("SSL")) {
            return AnsiColor.RED;
        } else {
            return AnsiColor.DEFAULT_COLOR;
        }
    }

    protected AnsiColor getColorForForwardSecrecy(Boolean forwardSecrecy) {
        if (forwardSecrecy == null) {
            return AnsiColor.DEFAULT_COLOR;
        }
        if (forwardSecrecy) {
            return AnsiColor.GREEN;
        } else {
            return AnsiColor.RED;
        }
    }

    protected AnsiColor getColorForDhModulusSize(Integer dhModulusSize) {
        if (dhModulusSize == null) {
            return AnsiColor.DEFAULT_COLOR;
        }
        if (dhModulusSize < 1024) {
            return AnsiColor.RED;
        }
        if (dhModulusSize < 2048) {
            return AnsiColor.YELLOW;
        }
        return AnsiColor.GREEN;
    }

    protected AnsiColor getColorForRecommendation(PropertyResultRatingInfluencer influencer) {
        if (influencer.getInfluence() <= -200) {
            return AnsiColor.RED;
        } else if (influencer.getInfluence() < 0) {
            return AnsiColor.YELLOW;
        } else if (influencer.getInfluence() > 0) {
            return AnsiColor.GREEN;
        }
        return AnsiColor.DEFAULT_COLOR;
    }
}
