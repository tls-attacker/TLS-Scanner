/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsscanner.constants.AnsiColors;
import de.rub.nds.tlsscanner.constants.CipherSuiteGrade;
import de.rub.nds.tlsscanner.constants.GcmPattern;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.MacCheckPattern;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SiteReport {

    //general
    private final List<ProbeType> probeTypeList;

    private final String host;
    private Boolean serverIsAlive = null;
    private Boolean supportsSslTls = null;

    //Quirks
    private Boolean requiresSni = null;

    private Boolean versionIntolerance = null;
    private Boolean extensionIntolerance = null;
    private Boolean cipherSuiteIntolerance = null;
    private Boolean groupsIntolerance = null;
    private Boolean clientHelloSizeIntolerance = null;
    private Boolean compressionIntolerance = null;
    private Boolean pointFormatsIntolerance = null;
    private Boolean signatureAndHashAlgorithmIntolerance = null;

    //Attacks
    private Boolean bleichenbacherVulnerable = null;
    private Boolean paddingOracleVulnerable = null;
    private Boolean invalidCurveVulnerable = null;
    private Boolean invalidCurveEphermaralVulnerable = null;
    private Boolean poodleVulnerable = null;
    private Boolean tlsPoodleVulnerable = null;
    private Boolean cve20162107Vulnerable = null;
    private Boolean crimeVulnerable = null;
    private Boolean breachVulnerable = null;
    private Boolean sweet32Vulnerable = null;
    private Boolean drownVulnerable = null;
    private Boolean logjamVulnerable = null;
    private Boolean lucky13Vulnerable = null;
    private Boolean heartbleedVulnerable = null;
    private Boolean earlyCcsVulnerable = null;
    private Boolean freakVulnerable = null;

    //Version
    private List<ProtocolVersion> versions = null;
    private Boolean supportsSsl2 = null;
    private Boolean supportsSsl3 = null;
    private Boolean supportsTls10 = null;
    private Boolean supportsTls11 = null;
    private Boolean supportsTls12 = null;
    private Boolean supportsTls13 = null;
    private Boolean supportsTls13Draft14 = null;
    private Boolean supportsTls13Draft15 = null;
    private Boolean supportsTls13Draft16 = null;
    private Boolean supportsTls13Draft17 = null;
    private Boolean supportsTls13Draft18 = null;
    private Boolean supportsTls13Draft19 = null;
    private Boolean supportsTls13Draft20 = null;
    private Boolean supportsTls13Draft21 = null;
    private Boolean supportsTls13Draft22 = null;
    private Boolean supportsTls13Draft23 = null;
    private Boolean supportsTls13Draft24 = null;
    private Boolean supportsTls13Draft25 = null;
    private Boolean supportsTls13Draft26 = null;
    private Boolean supportsDtls10 = null;
    private Boolean supportsDtls12 = null;
    private Boolean supportsDtls13 = null;

    //Extensions
    private List<ExtensionType> supportedExtensions = null;
    private List<NamedGroup> supportedNamedGroups = null;
    private List<NamedGroup> supportedTls13Groups = null;
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms = null;
    private List<TokenBindingVersion> supportedTokenBindingVersion = null;
    private List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters = null;
    private Boolean supportsExtendedMasterSecret = null;
    private Boolean supportsEncryptThenMacSecret = null;
    private Boolean supportsTokenbinding = null;

    //Compression
    private List<CompressionMethod> supportedCompressionMethods = null;

    //RFC
    private MacCheckPattern macCheckPatterAppData = null;
    private MacCheckPattern macCheckPatternFinished = null;
    private Boolean checksFinished = null;

    //Certificate
    private Certificate certificate = null;
    private List<CertificateReport> certificateReports = null;
    private Boolean certificateExpired = null;
    private Boolean certificateNotYetValid = null;
    private Boolean certificateHasWeakHashAlgorithm = null;
    private Boolean certificateHasWeakSignAlgorithm = null;
    private Boolean certificateMachtesDomainName = null;
    private Boolean certificateIsTrusted = null;
    private Boolean certificateKeyIsBlacklisted = null;

    //Ciphers
    private List<VersionSuiteListPair> versionSuitePairs = null;
    private List<CipherSuite> cipherSuites = null;
    private List<CipherSuite> supportedTls13CipherSuites = null;
    private Boolean supportsNullCiphers = null;
    private Boolean supportsAnonCiphers = null;
    private Boolean supportsExportCiphers = null;
    private Boolean supportsDesCiphers = null;
    private Boolean supportsSeedCiphers = null;
    private Boolean supportsIdeaCiphers = null;
    private Boolean supportsRc2Ciphers = null;
    private Boolean supportsRc4Ciphers = null;
    private Boolean supportsTrippleDesCiphers = null;
    private Boolean supportsPostQuantumCiphers = null;
    private Boolean supportsAeadCiphers = null;
    private Boolean supportsPfsCiphers = null;
    private Boolean supportsOnlyPfsCiphers = null;
    private Boolean enforcesCipherSuiteOrdering = null;
    private Boolean supportsAes = null;
    private Boolean supportsCamellia = null;
    private Boolean supportsAria = null;
    private Boolean supportsChacha = null;
    private Boolean supportsRsa = null;
    private Boolean supportsDh = null;
    private Boolean supportsEcdh = null;
    private Boolean supportsStaticEcdh = null;
    private Boolean supportsGost = null;
    private Boolean supportsSrp = null;
    private Boolean supportsKerberos = null;
    private Boolean supportsPskPlain = null;
    private Boolean supportsPskRsa = null;
    private Boolean supportsPskDhe = null;
    private Boolean supportsPskEcdhe = null;
    private Boolean supportsFortezza = null;
    private Boolean supportsNewHope = null;
    private Boolean supportsEcmqv = null;
    private Boolean prefersPfsCiphers = null;
    private Boolean supportsStreamCiphers = null;
    private Boolean supportsBlockCiphers = null;

    //Session
    private Boolean supportsSessionTicket = null;
    private Boolean supportsSessionIds = null;
    private Long sessionTicketLengthHint = null;
    private Boolean sessionTicketGetsRotated = null;
    private Boolean vulnerableTicketBleed = null;

    //Renegotiation + SCSV
    private Boolean supportsSecureRenegotiation = null;
    private Boolean supportsClientSideSecureRenegotiation = null;
    private Boolean supportsClientSideInsecureRenegotiation = null;
    private Boolean tlsFallbackSCSVsupported = null;

    //GCM Nonces
    private Boolean gcmReuse = null;
    private GcmPattern gcmPattern = null;
    private Boolean gcmCheck = null;

    public SiteReport(String host, List<ProbeType> probeTypeList) {
        this.host = host;
        this.probeTypeList = probeTypeList;
    }

    public String getHost() {
        return host;
    }

    public String getStringReport() {
        StringBuilder builder = new StringBuilder();
        builder.append("Report for ");
        builder.append(host);
        builder.append("\n");
        if (serverIsAlive == Boolean.FALSE) {
            builder.append("Cannot reach the Server. Is it online?");
            return builder.toString();
        }
        if (supportsSslTls == Boolean.FALSE) {
            builder.append("Server does not seem to support SSL / TLS");
            return builder.toString();
        }

        appendProtocolVersions(builder);
        appendCipherSuites(builder);
        appendExtensions(builder);
        appendCompressions(builder);
        appendIntolerances(builder);
        appendAttackVulnerabilities(builder);
        appendGcm(builder);
        appendRfc(builder);
        appendCertificate(builder);
        appendSession(builder);
        appendRenegotiation(builder);
        return builder.toString();
    }

    private StringBuilder appendRfc(StringBuilder builder) {
        builder.append("----------RFC----------\n");
        prettyAppendMacCheckPattern(builder, "Checks Mac (in AppData)", macCheckPatterAppData);
        prettyAppendMacCheckPattern(builder, "Checks Mac (in Finished)", macCheckPatternFinished);
        prettyAppendRedOnFailure(builder, "Checks VerifyData", checksFinished);
        return builder;
    }

    private StringBuilder appendRenegotiation(StringBuilder builder) {
        builder.append("----------Renegotiation & SCSV----------\n");
        prettyAppendYellowOnSuccess(builder, "Clientside Secure", supportsClientSideSecureRenegotiation);
        prettyAppendRedOnSuccess(builder, "Clientside Insecure", supportsClientSideInsecureRenegotiation);
        prettyAppendRedOnFailure(builder, "SCSV Fallback", tlsFallbackSCSVsupported);
        return builder;
    }

    private StringBuilder appendCertificate(StringBuilder builder) {
        if (certificateReports != null && !certificateReports.isEmpty()) {
            builder.append("----------Certificates----------\n");
            for (CertificateReport report : certificateReports) {
                builder.append(report.toString()).append("\n");
            }
            builder.append("----------Certificate Checks----------\n");
            prettyAppendRedOnSuccess(builder, "Expired Certificates", certificateExpired);
            prettyAppendRedOnSuccess(builder, "Not yet Valid Certificates", certificateNotYetValid);
            prettyAppendRedOnSuccess(builder, "Weak Hash Algorithms", certificateHasWeakHashAlgorithm);
            prettyAppendRedOnSuccess(builder, "Weak Signature Algorithms", certificateHasWeakSignAlgorithm);
            prettyAppendRedOnFailure(builder, "Matches Domain", certificateMachtesDomainName);
            prettyAppendGreenOnSuccess(builder, "Only Trusted", certificateIsTrusted);
            prettyAppendRedOnFailure(builder, "Contains Blacklisted", certificateKeyIsBlacklisted);
        }
        return builder;
    }

    private StringBuilder appendSession(StringBuilder builder) {
        builder.append("----------Session----------\n");
        prettyAppendYellowOnFailure(builder, "Supports Session resumption", supportsSessionIds);
        prettyAppendYellowOnFailure(builder, "Supports Session Tickets", supportsSessionTicket);
        prettyAppend(builder, "Session Ticket Hint:" + sessionTicketLengthHint);
        prettyAppendYellowOnFailure(builder, "Session Ticket Rotation", sessionTicketGetsRotated);
        prettyAppendRedOnFailure(builder, "Ticketbleed", vulnerableTicketBleed);
        return builder;
    }

    private StringBuilder appendGcm(StringBuilder builder) {
        builder.append("----------GCM----------\n");
        prettyAppendRedOnFailure(builder, "GCM Nonce reuse", gcmReuse);
        if (gcmPattern == null) {
            prettyAppend(builder, "GCM Pattern: Unknown");
        } else if (gcmPattern == GcmPattern.AKWARD) {
            prettyAppendYellow(builder, "GCM Pattern: " + gcmPattern.name());
        } else if (gcmPattern == GcmPattern.INCREMENTING) {
            prettyAppendGreen(builder, "GCM Pattern: " + gcmPattern.name());
        } else if (gcmPattern == GcmPattern.RANDOM) {
            prettyAppendGreen(builder, "GCM Pattern: " + gcmPattern.name());
        } else if (gcmPattern == GcmPattern.REPEATING) {
            prettyAppendRed(builder, "GCM Pattern: " + gcmPattern.name());
        } else {
            prettyAppend(builder, "GCM Pattern: " + gcmPattern.name());
        }
        prettyAppendRedOnFailure(builder, "GCM Check", gcmCheck);
        return builder;
    }

    private StringBuilder appendIntolerances(StringBuilder builder) {
        builder.append("----------Intolerances----------\n");
        prettyAppendRedOnFailure(builder, "Version", versionIntolerance);
        prettyAppendRedOnFailure(builder, "Ciphersuite", cipherSuiteIntolerance);
        prettyAppendRedOnFailure(builder, "Extension", extensionIntolerance);
        prettyAppendRedOnFailure(builder, "Curves", groupsIntolerance);
        prettyAppendRedOnFailure(builder, "ClientHello Size", clientHelloSizeIntolerance);
        prettyAppendRedOnFailure(builder, "Compression", compressionIntolerance);
        prettyAppendRedOnFailure(builder, "Signature and Hash", signatureAndHashAlgorithmIntolerance);
        prettyAppendRedOnFailure(builder, "Point Formats", pointFormatsIntolerance);
        return builder;
    }

    private StringBuilder appendAttackVulnerabilities(StringBuilder builder) {
        builder.append("----------Attack Vulnerabilities----------\n");
        prettyAppendRedGreen(builder, "Padding Oracle", paddingOracleVulnerable);
        prettyAppendRedGreen(builder, "Bleichenbacher", bleichenbacherVulnerable);
        prettyAppendRedGreen(builder, "CRIME", crimeVulnerable);
        prettyAppendRedGreen(builder, "Breach", breachVulnerable);
        prettyAppendRedGreen(builder, "Invalid Curve", invalidCurveVulnerable);
        prettyAppendRedGreen(builder, "Invalid Curve Ephemerals", invalidCurveEphermaralVulnerable);
        prettyAppendRedGreen(builder, "SSL Poodle", poodleVulnerable);
        prettyAppendRedGreen(builder, "TLS Poodle", tlsPoodleVulnerable);
        prettyAppendRedGreen(builder, "CVE-20162107", cve20162107Vulnerable);
        prettyAppendRedGreen(builder, "Logjam", logjamVulnerable);
        prettyAppendRedGreen(builder, "Sweet 32", sweet32Vulnerable);
        prettyAppendRedGreen(builder, "DROWN", drownVulnerable);
        prettyAppendRedGreen(builder, "Lucky13", lucky13Vulnerable);
        prettyAppendRedGreen(builder, "Heartbleed", heartbleedVulnerable);
        prettyAppendRedGreen(builder, "EarlyCcs", earlyCcsVulnerable);
        prettyAppendRedGreen(builder, "FREAK", freakVulnerable);
        return builder;
    }

    private StringBuilder appendCipherSuites(StringBuilder builder) {
        if (cipherSuites != null) {
            builder.append("----------Supported Ciphersuites----------\n");
            for (CipherSuite suite : cipherSuites) {
                prettyPrintCipherSuite(builder, suite);
            }

            for (VersionSuiteListPair versionSuitePair : versionSuitePairs) {
                builder.append("----------Supported in " + versionSuitePair.getVersion() + "----------\n");
                for (CipherSuite suite : versionSuitePair.getCiphersuiteList()) {
                    prettyPrintCipherSuite(builder, suite);
                }
            }
            builder.append("----------Symmetric Supported----------\n");
            prettyAppendRedOnSuccess(builder, "Null", supportsNullCiphers);
            prettyAppendRedOnSuccess(builder, "Export", supportsExportCiphers);
            prettyAppendRedOnSuccess(builder, "Anon", supportsAnonCiphers);
            prettyAppendRedOnSuccess(builder, "DES", supportsDesCiphers);
            prettyAppendYellowOnSuccess(builder, "SEED", supportsSeedCiphers);
            prettyAppendYellowOnSuccess(builder, "IDEA", supportsIdeaCiphers);
            prettyAppendRedOnSuccess(builder, "RC2", supportsRc2Ciphers);
            prettyAppendRedOnSuccess(builder, "RC4", supportsRc4Ciphers);
            prettyAppendYellowOnSuccess(builder, "3DES", supportsTrippleDesCiphers);
            prettyAppend(builder, "AES", supportsAes);
            prettyAppend(builder, "CAMELLIA", supportsCamellia);
            prettyAppend(builder, "ARIA", supportsAria);
            prettyAppendGreenOnSuccess(builder, "CHACHA20 POLY1305", supportsChacha);
            builder.append("----------KeyExchange Supported----------\n");
            prettyAppendYellowOnSuccess(builder, "RSA", supportsRsa);
            prettyAppend(builder, "DH", supportsDh);
            prettyAppend(builder, "ECDH", supportsEcdh);
            prettyAppend(builder, "Static ECDH", supportsStaticEcdh);
            prettyAppendYellowOnSuccess(builder, "GOST", supportsGost);
            prettyAppend(builder, "SRP", supportsSrp);
            prettyAppend(builder, "Kerberos", supportsKerberos);
            prettyAppend(builder, "Plain PSK", supportsPskPlain);
            prettyAppend(builder, "PSK RSA", supportsPskRsa);
            prettyAppend(builder, "PSK DHE", supportsPskDhe);
            prettyAppend(builder, "PSK ECDHE", supportsPskEcdhe);
            prettyAppendYellowOnSuccess(builder, "Fortezza", supportsFortezza);
            prettyAppendGreenOnSuccess(builder, "New Hope", supportsNewHope);
            prettyAppendGreenOnSuccess(builder, "ECMQV", supportsEcmqv);
            builder.append("----------Perfect Forward Secrecy----------\n");
            prettyAppendGreenOnSuccess(builder, "Supports PFS", supportsPfsCiphers);
            prettyAppendGreenOnSuccess(builder, "Prefers PFS", prefersPfsCiphers);
            prettyAppendGreenOnSuccess(builder, "Supports Only PFS", supportsOnlyPfsCiphers);
            builder.append("----------Cipher Types Supports----------\n");
            prettyAppend(builder, "Stream", supportsStreamCiphers);
            prettyAppend(builder, "Block", supportsBlockCiphers);
            prettyAppendGreenOnSuccess(builder, "AEAD", supportsAeadCiphers);
            builder.append("----------Ciphersuite General----------\n");
            prettyAppendGreenRed(builder, "Enforces Ciphersuite ordering", enforcesCipherSuiteOrdering);
        }
        if (supportedTls13CipherSuites != null) {
            builder.append("----------TLS 1.3 Ciphersuites----------\n");
            if (supportedTls13CipherSuites.isEmpty()) {
                prettyAppend(builder, "none");
            } else {
                for (CipherSuite suite : supportedTls13CipherSuites) {
                    prettyPrintCipherSuite(builder, suite);
                }
            }
        }
        return builder;
    }

    private StringBuilder appendProtocolVersions(StringBuilder builder) {
        if (versions != null) {
            builder.append("----------Supported Protocol Versions----------\n");
            for (ProtocolVersion version : versions) {
                builder.append(version.name()).append("\n");
            }
            builder.append("----------Versions----------\n");
            prettyAppendRedGreen(builder, "SSL 2.0", supportsSsl2);
            prettyAppendRedGreen(builder, "SSL 3.0", supportsSsl3);
            prettyAppendYellowOnFailure(builder, "TLS 1.0", supportsTls10);
            prettyAppendYellowOnFailure(builder, "TLS 1.1", supportsTls11);
            prettyAppendRedOnFailure(builder, "TLS 1.2", supportsTls12);
            prettyAppendGreenOnSuccess(builder, "TLS 1.3", supportsTls13);
            prettyAppendYellowOnSuccess(builder, "TLS 1.3 Draft 14", supportsTls13Draft14);
            prettyAppendYellowOnSuccess(builder, "TLS 1.3 Draft 15", supportsTls13Draft15);
            prettyAppendYellowOnSuccess(builder, "TLS 1.3 Draft 16", supportsTls13Draft16);
            prettyAppendYellowOnSuccess(builder, "TLS 1.3 Draft 17", supportsTls13Draft17);
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 18", supportsTls13Draft18);
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 19", supportsTls13Draft19);
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 20", supportsTls13Draft20);
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 21", supportsTls13Draft21);
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 22", supportsTls13Draft22);
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 23", supportsTls13Draft23);
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 24", supportsTls13Draft24);
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 25", supportsTls13Draft25);
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 26", supportsTls13Draft26);
            //prettyAppend(builder, "DTLS 1.0", supportsDtls10);
            //prettyAppend(builder, "DTLS 1.2", supportsDtls10);
            //prettyAppend(builder, "DTLS 1.3", supportsDtls13);
        }
        return builder;
    }

    private StringBuilder appendExtensions(StringBuilder builder) {
        if (supportedExtensions != null) {
            builder.append("----------Supported Extensions----------\n");
            for (ExtensionType type : supportedExtensions) {
                builder.append(type.name()).append("\n");
            }
        }
        builder.append("----------Extensions----------\n");
        prettyAppendYellowOnSuccess(builder, "Requires SNI", requiresSni);
        prettyAppendGreenRed(builder, "Secure Renegotiation", supportsSecureRenegotiation);
        prettyAppendGreenOnSuccess(builder, "Supports Extended Master Secret", supportsExtendedMasterSecret);
        prettyAppendGreenOnSuccess(builder, "Supports Encrypt Then Mac", supportsEncryptThenMacSecret);
        prettyAppendGreenOnSuccess(builder, "Supports Tokenbinding", supportsTokenbinding);
        if (supportsTokenbinding == Boolean.TRUE) {
            builder.append("----------Tokenbinding Versions----------\n");
            for (TokenBindingVersion version : supportedTokenBindingVersion) {
                builder.append(version.toString()).append("\n");
            }
            builder.append("----------Tokenbinding Key Paramters----------\n");
            for (TokenBindingKeyParameters keyParameter : supportedTokenBindingKeyParameters) {
                builder.append(keyParameter.toString()).append("\n");
            }
        }
        appendCurves(builder);
        appendSignatureAndHashAlgorithms(builder);
        return builder;
    }

    private void prettyPrintCipherSuite(StringBuilder builder, CipherSuite suite) {
        CipherSuiteGrade grade = CiphersuiteRater.getGrade(suite);
        switch (grade) {
            case GOOD:
                prettyAppendGreen(builder, suite.name());
                break;
            case LOW:
                prettyAppendRed(builder, suite.name());
                break;
            case MEDIUM:
                prettyAppendYellow(builder, suite.name());
                break;
            case NONE:
                prettyAppend(builder, suite.name());
                break;
            default:
                prettyAppend(builder, suite.name());
        }
    }

    private StringBuilder appendCurves(StringBuilder builder) {
        if (supportedNamedGroups != null) {
            builder.append("----------Supported Named Groups----------\n");
            if (supportedNamedGroups.size() > 0) {
                for (NamedGroup group : supportedNamedGroups) {
                    builder.append(group.name()).append("\n");
                }
            } else {
                builder.append("none\n");
            }
        }
        if (supportedTls13Groups != null) {
            builder.append("----------TLS 1.3 Groups----------\n");
            if (supportedTls13Groups.size() > 0) {
                for (NamedGroup group : supportedTls13Groups) {
                    builder.append(group.name()).append("\n");
                }
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    private StringBuilder appendSignatureAndHashAlgorithms(StringBuilder builder) {
        if (supportedSignatureAndHashAlgorithms != null) {
            builder.append("----------Supported Signature and Hash Algorithms----------\n");
            if (supportedSignatureAndHashAlgorithms.size() > 0) {
                for (SignatureAndHashAlgorithm algorithm : supportedSignatureAndHashAlgorithms) {
                    prettyAppend(builder, algorithm.toString());
                }
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    private StringBuilder appendCompressions(StringBuilder builder) {
        if (supportedCompressionMethods != null) {
            builder.append("----------Supported Compressions----------\n");
            for (CompressionMethod compression : supportedCompressionMethods) {
                prettyAppend(builder, compression.name());
            }
        }
        return builder;
    }

    private StringBuilder prettyAppend(StringBuilder builder, String value) {
        return builder.append(value).append("\n");
    }

    private StringBuilder prettyAppend(StringBuilder builder, String name, Boolean value) {
        return builder.append(name).append(": ").append(value == null ? "Unknown" : value).append("\n");
    }

    private StringBuilder prettyAppendGreenOnSuccess(StringBuilder builder, String name, Boolean value) {
        return builder.append(name).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? AnsiColors.ANSI_GREEN + value + AnsiColors.ANSI_RESET : value)).append("\n");
    }

    private StringBuilder prettyAppendGreenOnFailure(StringBuilder builder, String name, Boolean value) {
        return builder.append(name).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? value : AnsiColors.ANSI_GREEN + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendRedOnSuccess(StringBuilder builder, String name, Boolean value) {
        return builder.append(name).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? AnsiColors.ANSI_RED + value + AnsiColors.ANSI_RESET : value)).append("\n");
    }

    private StringBuilder prettyAppendRedOnFailure(StringBuilder builder, String name, Boolean value) {
        return builder.append(name).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? value : AnsiColors.ANSI_RED + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendYellowOnFailure(StringBuilder builder, String name, Boolean value) {
        return builder.append(name).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? value : AnsiColors.ANSI_YELLOW + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendYellowOnSuccess(StringBuilder builder, String name, Boolean value) {
        return builder.append(name).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? AnsiColors.ANSI_YELLOW + value + AnsiColors.ANSI_RESET : value)).append("\n");
    }

    private StringBuilder prettyAppendGreenRed(StringBuilder builder, String name, Boolean value) {
        return builder.append(name).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? AnsiColors.ANSI_GREEN + value + AnsiColors.ANSI_RESET : AnsiColors.ANSI_RED + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendRedGreen(StringBuilder builder, String name, Boolean value) {
        return builder.append(name).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? AnsiColors.ANSI_RED + value + AnsiColors.ANSI_RESET : AnsiColors.ANSI_GREEN + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendYellow(StringBuilder builder, String value) {
        return builder.append(AnsiColors.ANSI_YELLOW + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendRed(StringBuilder builder, String value) {
        return builder.append(AnsiColors.ANSI_RED + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendGreen(StringBuilder builder, String value) {
        return builder.append(AnsiColors.ANSI_GREEN + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendMacCheckPattern(StringBuilder builder, String value, MacCheckPattern pattern) {
        if (pattern == null) {
            return builder.append(value).append(": ").append("null");
        }
        builder = builder.append(value).append(": ");
        switch (pattern.getType()) {
            case CORRECT:
                return prettyAppendGreen(builder, pattern.toString());
            case NONE:
            case PARTIAL:
                return prettyAppendRed(builder, pattern.toString());
            case UNKNOWN:
                return prettyAppend(builder, pattern.toString());
            default:
                throw new IllegalArgumentException("Unkown MacCheckPattern Type: " + pattern.getType());
        }
    }

    public Boolean getRequiresSni() {
        return requiresSni;
    }

    public void setRequiresSni(Boolean requiresSni) {
        this.requiresSni = requiresSni;
    }

    public Boolean getCompressionIntolerance() {
        return compressionIntolerance;
    }

    public void setCompressionIntolerance(Boolean compressionIntolerance) {
        this.compressionIntolerance = compressionIntolerance;
    }

    public Boolean getPointFormatsIntolerance() {
        return pointFormatsIntolerance;
    }

    public void setPointFormatsIntolerance(Boolean pointFormatsIntolerance) {
        this.pointFormatsIntolerance = pointFormatsIntolerance;
    }

    public Boolean getSignatureAndHashAlgorithmIntolerance() {
        return signatureAndHashAlgorithmIntolerance;
    }

    public void setSignatureAndHashAlgorithmIntolerance(Boolean signatureAndHashAlgorithmIntolerance) {
        this.signatureAndHashAlgorithmIntolerance = signatureAndHashAlgorithmIntolerance;
    }

    public Boolean getFreakVulnerable() {
        return freakVulnerable;
    }

    public void setFreakVulnerable(Boolean freakVulnerable) {
        this.freakVulnerable = freakVulnerable;
    }

    public Boolean getHeartbleedVulnerable() {
        return heartbleedVulnerable;
    }

    public void setHeartbleedVulnerable(Boolean heartbleedVulnerable) {
        this.heartbleedVulnerable = heartbleedVulnerable;
    }

    public Boolean getEarlyCcsVulnerable() {
        return earlyCcsVulnerable;
    }

    public void setEarlyCcsVulnerable(Boolean earlyCcsVulnerable) {
        this.earlyCcsVulnerable = earlyCcsVulnerable;
    }

    public Boolean getServerIsAlive() {
        return serverIsAlive;
    }

    public void setServerIsAlive(Boolean serverIsAlive) {
        this.serverIsAlive = serverIsAlive;
    }

    public Boolean getSupportsSsl2() {
        return supportsSsl2;
    }

    public void setSupportsSsl2(Boolean supportsSsl2) {
        this.supportsSsl2 = supportsSsl2;
    }

    public Boolean getSupportsSsl3() {
        return supportsSsl3;
    }

    public void setSupportsSsl3(Boolean supportsSsl3) {
        this.supportsSsl3 = supportsSsl3;
    }

    public Boolean getSupportsTls10() {
        return supportsTls10;
    }

    public void setSupportsTls10(Boolean supportsTls10) {
        this.supportsTls10 = supportsTls10;
    }

    public Boolean getSupportsTls11() {
        return supportsTls11;
    }

    public void setSupportsTls11(Boolean supportsTls11) {
        this.supportsTls11 = supportsTls11;
    }

    public Boolean getSupportsTls12() {
        return supportsTls12;
    }

    public void setSupportsTls12(Boolean supportsTls12) {
        this.supportsTls12 = supportsTls12;
    }

    public Boolean supportsAnyTls13() {
        return supportsTls13 == Boolean.TRUE || supportsTls13Draft14 == Boolean.TRUE || supportsTls13Draft15 == Boolean.TRUE || supportsTls13Draft16 == Boolean.TRUE || supportsTls13Draft17 == Boolean.TRUE || supportsTls13Draft18 == Boolean.TRUE || supportsTls13Draft19 == Boolean.TRUE || supportsTls13Draft20 == Boolean.TRUE || supportsTls13Draft21 == Boolean.TRUE || supportsTls13Draft22 == Boolean.TRUE;
    }

    public Boolean getSupportsTls13() {
        return supportsTls13;
    }

    public void setSupportsTls13(Boolean supportsTls13) {
        this.supportsTls13 = supportsTls13;
    }

    public Boolean getSupportsTls13Draft14() {
        return supportsTls13Draft14;
    }

    public void setSupportsTls13Draft14(Boolean supportsTls13Draft14) {
        this.supportsTls13Draft14 = supportsTls13Draft14;
    }

    public Boolean getSupportsTls13Draft15() {
        return supportsTls13Draft15;
    }

    public void setSupportsTls13Draft15(Boolean supportsTls13Draft15) {
        this.supportsTls13Draft15 = supportsTls13Draft15;
    }

    public Boolean getSupportsTls13Draft16() {
        return supportsTls13Draft16;
    }

    public void setSupportsTls13Draft16(Boolean supportsTls13Draft16) {
        this.supportsTls13Draft16 = supportsTls13Draft16;
    }

    public Boolean getSupportsTls13Draft17() {
        return supportsTls13Draft17;
    }

    public void setSupportsTls13Draft17(Boolean supportsTls13Draft17) {
        this.supportsTls13Draft17 = supportsTls13Draft17;
    }

    public Boolean getSupportsTls13Draft18() {
        return supportsTls13Draft18;
    }

    public void setSupportsTls13Draft18(Boolean supportsTls13Draft18) {
        this.supportsTls13Draft18 = supportsTls13Draft18;
    }

    public Boolean getSupportsTls13Draft19() {
        return supportsTls13Draft19;
    }

    public void setSupportsTls13Draft19(Boolean supportsTls13Draft19) {
        this.supportsTls13Draft19 = supportsTls13Draft19;
    }

    public Boolean getSupportsTls13Draft20() {
        return supportsTls13Draft20;
    }

    public void setSupportsTls13Draft20(Boolean supportsTls13Draft20) {
        this.supportsTls13Draft20 = supportsTls13Draft20;
    }

    public Boolean getSupportsTls13Draft21() {
        return supportsTls13Draft21;
    }

    public void setSupportsTls13Draft21(Boolean supportsTls13Draft21) {
        this.supportsTls13Draft21 = supportsTls13Draft21;
    }

    public Boolean getSupportsTls13Draft22() {
        return supportsTls13Draft22;
    }

    public void setSupportsTls13Draft22(Boolean supportsTls13Draft22) {
        this.supportsTls13Draft22 = supportsTls13Draft22;
    }

    public Boolean getSupportsTls13Draft23() {
        return supportsTls13Draft23;
    }

    public void setSupportsTls13Draft23(Boolean supportsTls13Draft23) {
        this.supportsTls13Draft23 = supportsTls13Draft23;
    }

    public Boolean getSupportsTls13Draft24() {
        return supportsTls13Draft24;
    }

    public void setSupportsTls13Draft24(Boolean supportsTls13Draft24) {
        this.supportsTls13Draft24 = supportsTls13Draft24;
    }

    public Boolean getSupportsTls13Draft25() {
        return supportsTls13Draft25;
    }

    public void setSupportsTls13Draft25(Boolean supportsTls13Draft25) {
        this.supportsTls13Draft25 = supportsTls13Draft25;
    }

    public Boolean getSupportsTls13Draft26() {
        return supportsTls13Draft26;
    }

    public void setSupportsTls13Draft26(Boolean supportsTls13Draft26) {
        this.supportsTls13Draft26 = supportsTls13Draft26;
    }

    public Boolean getSupportsDtls10() {
        return supportsDtls10;
    }

    public void setSupportsDtls10(Boolean supportsDtls10) {
        this.supportsDtls10 = supportsDtls10;
    }

    public Boolean getSupportsDtls12() {
        return supportsDtls12;
    }

    public void setSupportsDtls12(Boolean supportsDtls12) {
        this.supportsDtls12 = supportsDtls12;
    }

    public Boolean getSupportsDtls13() {
        return supportsDtls13;
    }

    public void setSupportsDtls13(Boolean supportsDtls13) {
        this.supportsDtls13 = supportsDtls13;
    }

    public List<TokenBindingVersion> getSupportedTokenBindingVersion() {
        return supportedTokenBindingVersion;
    }

    public void setSupportedTokenBindingVersion(List<TokenBindingVersion> supportedTokenBindingVersion) {
        this.supportedTokenBindingVersion = supportedTokenBindingVersion;
    }

    public List<TokenBindingKeyParameters> getSupportedTokenBindingKeyParameters() {
        return supportedTokenBindingKeyParameters;
    }

    public void setSupportedTokenBindingKeyParameters(List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters) {
        this.supportedTokenBindingKeyParameters = supportedTokenBindingKeyParameters;
    }

    public List<CertificateReport> getCertificateReports() {
        return certificateReports;
    }

    public void setCertificateReports(List<CertificateReport> certificateReports) {
        this.certificateReports = certificateReports;
    }

    public Boolean getSupportsAes() {
        return supportsAes;
    }

    public void setSupportsAes(Boolean supportsAes) {
        this.supportsAes = supportsAes;
    }

    public Boolean getSupportsCamellia() {
        return supportsCamellia;
    }

    public void setSupportsCamellia(Boolean supportsCamellia) {
        this.supportsCamellia = supportsCamellia;
    }

    public Boolean getSupportsAria() {
        return supportsAria;
    }

    public void setSupportsAria(Boolean supportsAria) {
        this.supportsAria = supportsAria;
    }

    public Boolean getSupportsChacha() {
        return supportsChacha;
    }

    public void setSupportsChacha(Boolean supportsChacha) {
        this.supportsChacha = supportsChacha;
    }

    public Boolean getSupportsRsa() {
        return supportsRsa;
    }

    public void setSupportsRsa(Boolean supportsRsa) {
        this.supportsRsa = supportsRsa;
    }

    public Boolean getSupportsDh() {
        return supportsDh;
    }

    public void setSupportsDh(Boolean supportsDh) {
        this.supportsDh = supportsDh;
    }

    public Boolean getSupportsEcdh() {
        return supportsEcdh;
    }

    public void setSupportsEcdh(Boolean supportsEcdh) {
        this.supportsEcdh = supportsEcdh;
    }

    public Boolean getSupportsGost() {
        return supportsGost;
    }

    public void setSupportsGost(Boolean supportsGost) {
        this.supportsGost = supportsGost;
    }

    public Boolean getSupportsSrp() {
        return supportsSrp;
    }

    public void setSupportsSrp(Boolean supportsSrp) {
        this.supportsSrp = supportsSrp;
    }

    public Boolean getSupportsKerberos() {
        return supportsKerberos;
    }

    public void setSupportsKerberos(Boolean supportsKerberos) {
        this.supportsKerberos = supportsKerberos;
    }

    public Boolean getSupportsPskPlain() {
        return supportsPskPlain;
    }

    public void setSupportsPskPlain(Boolean supportsPskPlain) {
        this.supportsPskPlain = supportsPskPlain;
    }

    public Boolean getSupportsPskRsa() {
        return supportsPskRsa;
    }

    public void setSupportsPskRsa(Boolean supportsPskRsa) {
        this.supportsPskRsa = supportsPskRsa;
    }

    public Boolean getSupportsPskDhe() {
        return supportsPskDhe;
    }

    public void setSupportsPskDhe(Boolean supportsPskDhe) {
        this.supportsPskDhe = supportsPskDhe;
    }

    public Boolean getSupportsPskEcdhe() {
        return supportsPskEcdhe;
    }

    public void setSupportsPskEcdhe(Boolean supportsPskEcdhe) {
        this.supportsPskEcdhe = supportsPskEcdhe;
    }

    public Boolean getSupportsFortezza() {
        return supportsFortezza;
    }

    public void setSupportsFortezza(Boolean supportsFortezza) {
        this.supportsFortezza = supportsFortezza;
    }

    public Boolean getSupportsNewHope() {
        return supportsNewHope;
    }

    public void setSupportsNewHope(Boolean supportsNewHope) {
        this.supportsNewHope = supportsNewHope;
    }

    public Boolean getSupportsEcmqv() {
        return supportsEcmqv;
    }

    public void setSupportsEcmqv(Boolean supportsEcmqv) {
        this.supportsEcmqv = supportsEcmqv;
    }

    public Boolean getPrefersPfsCiphers() {
        return prefersPfsCiphers;
    }

    public void setPrefersPfsCiphers(Boolean prefersPfsCiphers) {
        this.prefersPfsCiphers = prefersPfsCiphers;
    }

    public Boolean getSupportsStreamCiphers() {
        return supportsStreamCiphers;
    }

    public void setSupportsStreamCiphers(Boolean supportsStreamCiphers) {
        this.supportsStreamCiphers = supportsStreamCiphers;
    }

    public Boolean getSupportsBlockCiphers() {
        return supportsBlockCiphers;
    }

    public void setSupportsBlockCiphers(Boolean supportsBlockCiphers) {
        this.supportsBlockCiphers = supportsBlockCiphers;
    }

    public Boolean getGcmCheck() {
        return gcmCheck;
    }

    public void setGcmCheck(Boolean gcmCheck) {
        this.gcmCheck = gcmCheck;
    }

    public List<ProtocolVersion> getVersions() {
        return versions;
    }

    public void setVersions(List<ProtocolVersion> versions) {
        this.versions = versions;
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(List<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public List<CipherSuite> getSupportedTls13CipherSuites() {
        return supportedTls13CipherSuites;
    }

    public void setSupportedTls13CipherSuites(List<CipherSuite> supportedTls13CipherSuites) {
        this.supportedTls13CipherSuites = supportedTls13CipherSuites;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public Boolean getBleichenbacherVulnerable() {
        return bleichenbacherVulnerable;
    }

    public void setBleichenbacherVulnerable(Boolean bleichenbacherVulnerable) {
        this.bleichenbacherVulnerable = bleichenbacherVulnerable;
    }

    public Boolean getPaddingOracleVulnerable() {
        return paddingOracleVulnerable;
    }

    public void setPaddingOracleVulnerable(Boolean paddingOracleVulnerable) {
        this.paddingOracleVulnerable = paddingOracleVulnerable;
    }

    public Boolean getInvalidCurveVulnerable() {
        return invalidCurveVulnerable;
    }

    public void setInvalidCurveVulnerable(Boolean invalidCurveVulnerable) {
        this.invalidCurveVulnerable = invalidCurveVulnerable;
    }

    public Boolean getInvalidCurveEphermaralVulnerable() {
        return invalidCurveEphermaralVulnerable;
    }

    public void setInvalidCurveEphermaralVulnerable(Boolean invalidCurveEphermaralVulnerable) {
        this.invalidCurveEphermaralVulnerable = invalidCurveEphermaralVulnerable;
    }

    public Boolean getPoodleVulnerable() {
        return poodleVulnerable;
    }

    public void setPoodleVulnerable(Boolean poodleVulnerable) {
        this.poodleVulnerable = poodleVulnerable;
    }

    public Boolean getTlsPoodleVulnerable() {
        return tlsPoodleVulnerable;
    }

    public void setTlsPoodleVulnerable(Boolean tlsPoodleVulnerable) {
        this.tlsPoodleVulnerable = tlsPoodleVulnerable;
    }

    public Boolean getCve20162107Vulnerable() {
        return cve20162107Vulnerable;
    }

    public void setCve20162107Vulnerable(Boolean cve20162107Vulnerable) {
        this.cve20162107Vulnerable = cve20162107Vulnerable;
    }

    public Boolean getCrimeVulnerable() {
        return crimeVulnerable;
    }

    public void setCrimeVulnerable(Boolean crimeVulnerable) {
        this.crimeVulnerable = crimeVulnerable;
    }

    public Boolean getBreachVulnerable() {
        return breachVulnerable;
    }

    public void setBreachVulnerable(Boolean breachVulnerable) {
        this.breachVulnerable = breachVulnerable;
    }

    public Boolean getEnforcesCipherSuiteOrdering() {
        return enforcesCipherSuiteOrdering;
    }

    public void setEnforcesCipherSuiteOrdering(Boolean enforcesCipherSuiteOrdering) {
        this.enforcesCipherSuiteOrdering = enforcesCipherSuiteOrdering;
    }

    public List<NamedGroup> getSupportedNamedGroups() {
        return supportedNamedGroups;
    }

    public void setSupportedNamedGroups(List<NamedGroup> supportedNamedGroups) {
        this.supportedNamedGroups = supportedNamedGroups;
    }

    public List<NamedGroup> getSupportedTls13Groups() {
        return supportedTls13Groups;
    }

    public void setSupportedTls13Groups(List<NamedGroup> supportedTls13Groups) {
        this.supportedTls13Groups = supportedTls13Groups;
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        return supportedSignatureAndHashAlgorithms;
    }

    public void setSupportedSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
        this.supportedSignatureAndHashAlgorithms = supportedSignatureAndHashAlgorithms;
    }

    public List<ExtensionType> getSupportedExtensions() {
        return supportedExtensions;
    }

    public void setSupportedExtensions(List<ExtensionType> supportedExtensions) {
        this.supportedExtensions = supportedExtensions;
    }

    public List<CompressionMethod> getSupportedCompressionMethods() {
        return supportedCompressionMethods;
    }

    public void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public MacCheckPattern getMacCheckPatternAppData() {
        return macCheckPatterAppData;
    }

    public void setMacCheckPatterAppData(MacCheckPattern macCheckPatterAppData) {
        this.macCheckPatterAppData = macCheckPatterAppData;
    }

    public Boolean getChecksFinished() {
        return checksFinished;
    }

    public void setChecksFinished(Boolean checksFinished) {
        this.checksFinished = checksFinished;
    }

    public Boolean getSupportsExtendedMasterSecret() {
        return supportsExtendedMasterSecret;
    }

    public void setSupportsExtendedMasterSecret(Boolean supportsExtendedMasterSecret) {
        this.supportsExtendedMasterSecret = supportsExtendedMasterSecret;
    }

    public Boolean getSupportsEncryptThenMacSecret() {
        return supportsEncryptThenMacSecret;
    }

    public void setSupportsEncryptThenMacSecret(Boolean supportsEncryptThenMacSecret) {
        this.supportsEncryptThenMacSecret = supportsEncryptThenMacSecret;
    }

    public Boolean getSupportsTokenbinding() {
        return supportsTokenbinding;
    }

    public void setSupportsTokenbinding(Boolean supportsTokenbinding) {
        this.supportsTokenbinding = supportsTokenbinding;
    }

    public Boolean getSupportsSslTls() {
        return supportsSslTls;
    }

    public void setSupportsSslTls(Boolean supportsSslTls) {
        this.supportsSslTls = supportsSslTls;
    }

    public Boolean getCertificateExpired() {
        return certificateExpired;
    }

    public void setCertificateExpired(Boolean certificateExpired) {
        this.certificateExpired = certificateExpired;
    }

    public Boolean getCertificateNotYetValid() {
        return certificateNotYetValid;
    }

    public void setCertificateNotYetValid(Boolean certificateNotYetValid) {
        this.certificateNotYetValid = certificateNotYetValid;
    }

    public Boolean getCertificateHasWeakHashAlgorithm() {
        return certificateHasWeakHashAlgorithm;
    }

    public void setCertificateHasWeakHashAlgorithm(Boolean certificateHasWeakHashAlgorithm) {
        this.certificateHasWeakHashAlgorithm = certificateHasWeakHashAlgorithm;
    }

    public Boolean getCertificateHasWeakSignAlgorithm() {
        return certificateHasWeakSignAlgorithm;
    }

    public void setCertificateHasWeakSignAlgorithm(Boolean certificateHasWeakSignAlgorithm) {
        this.certificateHasWeakSignAlgorithm = certificateHasWeakSignAlgorithm;
    }

    public Boolean getCertificateMachtesDomainName() {
        return certificateMachtesDomainName;
    }

    public void setCertificateMachtesDomainName(Boolean certificateMachtesDomainName) {
        this.certificateMachtesDomainName = certificateMachtesDomainName;
    }

    public Boolean getCertificateIsTrusted() {
        return certificateIsTrusted;
    }

    public void setCertificateIsTrusted(Boolean certificateIsTrusted) {
        this.certificateIsTrusted = certificateIsTrusted;
    }

    public Boolean getCertificateKeyIsBlacklisted() {
        return certificateKeyIsBlacklisted;
    }

    public void setCertificateKeyIsBlacklisted(Boolean certificateKeyIsBlacklisted) {
        this.certificateKeyIsBlacklisted = certificateKeyIsBlacklisted;
    }

    public Boolean getSupportsNullCiphers() {
        return supportsNullCiphers;
    }

    public void setSupportsNullCiphers(Boolean supportsNullCiphers) {
        this.supportsNullCiphers = supportsNullCiphers;
    }

    public Boolean getSupportsAnonCiphers() {
        return supportsAnonCiphers;
    }

    public void setSupportsAnonCiphers(Boolean supportsAnonCiphers) {
        this.supportsAnonCiphers = supportsAnonCiphers;
    }

    public Boolean getSupportsExportCiphers() {
        return supportsExportCiphers;
    }

    public void setSupportsExportCiphers(Boolean supportsExportCiphers) {
        this.supportsExportCiphers = supportsExportCiphers;
    }

    public Boolean getSupportsDesCiphers() {
        return supportsDesCiphers;
    }

    public void setSupportsDesCiphers(Boolean supportsDesCiphers) {
        this.supportsDesCiphers = supportsDesCiphers;
    }

    public Boolean getSupportsSeedCiphers() {
        return supportsSeedCiphers;
    }

    public void setSupportsSeedCiphers(Boolean supportsSeedCiphers) {
        this.supportsSeedCiphers = supportsSeedCiphers;
    }

    public Boolean getSupportsIdeaCiphers() {
        return supportsIdeaCiphers;
    }

    public void setSupportsIdeaCiphers(Boolean supportsIdeaCiphers) {
        this.supportsIdeaCiphers = supportsIdeaCiphers;
    }

    public Boolean getSupportsRc2Ciphers() {
        return supportsRc2Ciphers;
    }

    public void setSupportsRc2Ciphers(Boolean supportsRc2Ciphers) {
        this.supportsRc2Ciphers = supportsRc2Ciphers;
    }

    public Boolean getSupportsRc4Ciphers() {
        return supportsRc4Ciphers;
    }

    public void setSupportsRc4Ciphers(Boolean supportsRc4Ciphers) {
        this.supportsRc4Ciphers = supportsRc4Ciphers;
    }

    public Boolean getSupportsTrippleDesCiphers() {
        return supportsTrippleDesCiphers;
    }

    public void setSupportsTrippleDesCiphers(Boolean supportsTrippleDesCiphers) {
        this.supportsTrippleDesCiphers = supportsTrippleDesCiphers;
    }

    public Boolean getSupportsPostQuantumCiphers() {
        return supportsPostQuantumCiphers;
    }

    public void setSupportsPostQuantumCiphers(Boolean supportsPostQuantumCiphers) {
        this.supportsPostQuantumCiphers = supportsPostQuantumCiphers;
    }

    public Boolean getSupportsAeadCiphers() {
        return supportsAeadCiphers;
    }

    public void setSupportsAeadCiphers(Boolean supportsAeadCiphers) {
        this.supportsAeadCiphers = supportsAeadCiphers;
    }

    public Boolean getSupportsPfsCiphers() {
        return supportsPfsCiphers;
    }

    public void setSupportsPfsCiphers(Boolean supportsPfsCiphers) {
        this.supportsPfsCiphers = supportsPfsCiphers;
    }

    public Boolean getSupportsOnlyPfsCiphers() {
        return supportsOnlyPfsCiphers;
    }

    public void setSupportsOnlyPfsCiphers(Boolean supportsOnlyPfsCiphers) {
        this.supportsOnlyPfsCiphers = supportsOnlyPfsCiphers;
    }

    public Boolean getSupportsSessionTicket() {
        return supportsSessionTicket;
    }

    public void setSupportsSessionTicket(Boolean supportsSessionTicket) {
        this.supportsSessionTicket = supportsSessionTicket;
    }

    public Boolean getSupportsSessionIds() {
        return supportsSessionIds;
    }

    public void setSupportsSessionIds(Boolean supportsSessionIds) {
        this.supportsSessionIds = supportsSessionIds;
    }

    public Long getSessionTicketLengthHint() {
        return sessionTicketLengthHint;
    }

    public void setSessionTicketLengthHint(Long sessionTicketLengthHint) {
        this.sessionTicketLengthHint = sessionTicketLengthHint;
    }

    public Boolean getSessionTicketGetsRotated() {
        return sessionTicketGetsRotated;
    }

    public void setSessionTicketGetsRotated(Boolean sessionTicketGetsRotated) {
        this.sessionTicketGetsRotated = sessionTicketGetsRotated;
    }

    public Boolean getVulnerableTicketBleed() {
        return vulnerableTicketBleed;
    }

    public void setVulnerableTicketBleed(Boolean vulnerableTicketBleed) {
        this.vulnerableTicketBleed = vulnerableTicketBleed;
    }

    public Boolean getSupportsSecureRenegotiation() {
        return supportsSecureRenegotiation;
    }

    public void setSupportsSecureRenegotiation(Boolean supportsSecureRenegotiation) {
        this.supportsSecureRenegotiation = supportsSecureRenegotiation;
    }

    public Boolean getSupportsClientSideSecureRenegotiation() {
        return supportsClientSideSecureRenegotiation;
    }

    public void setSupportsClientSideSecureRenegotiation(Boolean supportsClientSideSecureRenegotiation) {
        this.supportsClientSideSecureRenegotiation = supportsClientSideSecureRenegotiation;
    }

    public Boolean getSupportsClientSideInsecureRenegotiation() {
        return supportsClientSideInsecureRenegotiation;
    }

    public void setSupportsClientSideInsecureRenegotiation(Boolean supportsClientSideInsecureRenegotiation) {
        this.supportsClientSideInsecureRenegotiation = supportsClientSideInsecureRenegotiation;
    }

    public Boolean getTlsFallbackSCSVsupported() {
        return tlsFallbackSCSVsupported;
    }

    public void setTlsFallbackSCSVsupported(Boolean tlsFallbackSCSVsupported) {
        this.tlsFallbackSCSVsupported = tlsFallbackSCSVsupported;
    }

    public Boolean getSweet32Vulnerable() {
        return sweet32Vulnerable;
    }

    public void setSweet32Vulnerable(Boolean sweet32Vulnerable) {
        this.sweet32Vulnerable = sweet32Vulnerable;
    }

    public Boolean getDrownVulnerable() {
        return drownVulnerable;
    }

    public void setDrownVulnerable(Boolean drownVulnerable) {
        this.drownVulnerable = drownVulnerable;
    }

    public Boolean getLogjamVulnerable() {
        return logjamVulnerable;
    }

    public void setLogjamVulnerable(Boolean logjamVulnerable) {
        this.logjamVulnerable = logjamVulnerable;
    }

    public Boolean getVersionIntolerance() {
        return versionIntolerance;
    }

    public void setVersionIntolerance(Boolean versionIntolerance) {
        this.versionIntolerance = versionIntolerance;
    }

    public Boolean getExtensionIntolerance() {
        return extensionIntolerance;
    }

    public void setExtensionIntolerance(Boolean extensionIntolerance) {
        this.extensionIntolerance = extensionIntolerance;
    }

    public Boolean getCipherSuiteIntolerance() {
        return cipherSuiteIntolerance;
    }

    public void setCipherSuiteIntolerance(Boolean cipherSuiteIntolerance) {
        this.cipherSuiteIntolerance = cipherSuiteIntolerance;
    }

    public Boolean getGroupsIntolerance() {
        return groupsIntolerance;
    }

    public void setGroupsIntolerance(Boolean groupsIntolerance) {
        this.groupsIntolerance = groupsIntolerance;
    }

    public Boolean getLucky13Vulnerable() {
        return lucky13Vulnerable;
    }

    public void setLucky13Vulnerable(Boolean lucky13Vulnerable) {
        this.lucky13Vulnerable = lucky13Vulnerable;
    }

    public Boolean getGcmReuse() {
        return gcmReuse;
    }

    public void setGcmReuse(Boolean gcmReuse) {
        this.gcmReuse = gcmReuse;
    }

    public GcmPattern getGcmPattern() {
        return gcmPattern;
    }

    public void setGcmPattern(GcmPattern gcmPattern) {
        this.gcmPattern = gcmPattern;
    }

    public List<VersionSuiteListPair> getVersionSuitePairs() {
        return versionSuitePairs;
    }

    public void setVersionSuitePairs(List<VersionSuiteListPair> versionSuitePairs) {
        this.versionSuitePairs = versionSuitePairs;
    }

    public Boolean getClientHelloSizeIntolerance() {
        return clientHelloSizeIntolerance;
    }

    public void setClientHelloSizeIntolerance(Boolean clientHelloSizeIntolerance) {
        this.clientHelloSizeIntolerance = clientHelloSizeIntolerance;
    }

    public Boolean getSupportsStaticEcdh() {
        return supportsStaticEcdh;
    }

    public void setSupportsStaticEcdh(Boolean supportsStaticEcdh) {
        this.supportsStaticEcdh = supportsStaticEcdh;
    }

    @Override
    public String toString() {
        return getStringReport();
    }

    public List<ProbeType> getProbeTypeList() {
        return probeTypeList;
    }

    public MacCheckPattern getMacCheckPatternFinished() {
        return macCheckPatternFinished;
    }

    public void setMacCheckPatternFinished(MacCheckPattern macCheckPatternFinished) {
        this.macCheckPatternFinished = macCheckPatternFinished;
    }
}
