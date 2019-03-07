/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
import de.rub.nds.tlsscanner.constants.AnsiColors;
import de.rub.nds.tlsscanner.constants.CipherSuiteGrade;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.report.after.prime.CommonDhValues;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.bleichenbacher.BleichenbacherTestResult;
import de.rub.nds.tlsscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleTestResult;
import de.rub.nds.tlsscanner.report.result.statistics.RandomEvaluationResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.Date;

public class SiteReportPrinter {

    private static final Logger LOGGER = LogManager.getLogger(SiteReportPrinter.class.getName());

    private final SiteReport report;
    private final ScannerDetail detail;

    public SiteReportPrinter(SiteReport report, ScannerDetail detail) {
        this.report = report;
        this.detail = detail;
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
        appendGcm(builder);
        appendRfc(builder);
        appendCertificate(builder);
        appendSession(builder);
        appendRenegotiation(builder);
        appendHttps(builder);
        appendRandom(builder);
        appendPublicKeyIssues(builder);
        for (PerformanceData data : report.getPerformanceList()) {
            LOGGER.debug("Type: " + data.getType() + "   Start: " + data.getStarttime() + "    Stop: " + data.getStoptime());
        }
        return builder.toString();
    }

    private StringBuilder appendRfc(StringBuilder builder) {
        prettyAppendHeading(builder, "RFC");
        prettyAppendCheckPattern(builder, "Checks MAC (AppData)", report.getMacCheckPatternAppData());
        prettyAppendCheckPattern(builder, "Checks MAC (Finished)", report.getMacCheckPatternFinished());
        prettyAppendCheckPattern(builder, "Checks VerifyData", report.getVerifyCheckPattern());
        return builder;
    }

    private StringBuilder appendRenegotiation(StringBuilder builder) {
        prettyAppendHeading(builder, "Renegotioation & SCSV");
        prettyAppendYellowOnSuccess(builder, "Clientside Secure", report.getSupportsClientSideSecureRenegotiation());
        prettyAppendRedOnSuccess(builder, "Clientside Insecure", report.getSupportsClientSideInsecureRenegotiation());
        prettyAppendRedOnFailure(builder, "SCSV Fallback", report.getTlsFallbackSCSVsupported());
        return builder;
    }

    private StringBuilder appendCertificate(StringBuilder builder) {
        if (report.getCertificateReports() != null && !report.getCertificateReports().isEmpty()) {
            prettyAppendHeading(builder, "Certificates");
            for (CertificateReport report : report.getCertificateReports()) {
                prettyAppend(builder, "Fingerprint", report.getSHA256Fingerprint());
                if (report.getSubject() != null) {
                    prettyAppend(builder, "Subject", report.getSubject());
                }
                if (report.getCommonNames() != null) {
                    prettyAppend(builder, "CommonNames", report.getCommonNames());
                }
                if (report.getAlternativenames() != null) {
                    prettyAppend(builder, "AltNames", report.getAlternativenames());
                }
                if (report.getValidFrom() != null) {
                    if (report.getValidFrom().before(new Date())) {
                        prettyAppendGreen(builder, "Valid From", report.getValidFrom().toString());
                    } else {
                        prettyAppendRed(builder, "Valid From", report.getValidFrom().toString());
                    }
                }
                if (report.getValidTo() != null) {
                    if (report.getValidTo().after(new Date())) {
                        prettyAppendGreen(builder, "Valid Till", report.getValidTo().toString());
                    } else {
                        prettyAppendRed(builder, "Valid Till", report.getValidTo().toString());
                    }

                }
                if (report.getPublicKey() != null) {
                    prettyAppend(builder, "PublicKey", report.getPublicKey().toString());
                }
                if (report.getWeakDebianKey() != null) {
                    prettyAppendRedGreen(builder, "Weak Debian Key", report.getWeakDebianKey());
                }
                if (report.getIssuer() != null) {
                    prettyAppend(builder, "Issuer", report.getIssuer());
                }
                if (report.getSignatureAndHashAlgorithm() != null) {
                    prettyAppend(builder, "Signature Algorithm", report.getSignatureAndHashAlgorithm().getSignatureAlgorithm().name());
                }
                if (report.getSignatureAndHashAlgorithm() != null) {
                    if (report.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.SHA1 || report.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.MD5) {
                        prettyAppendRed(builder, "Hash Algorithm", report.getSignatureAndHashAlgorithm().getHashAlgorithm().name());
                    } else {
                        prettyAppendGreen(builder, "Hash Algorithm", report.getSignatureAndHashAlgorithm().getHashAlgorithm().name());
                    }
                }
                if (report.getExtendedValidation() != null) {
                    prettyAppendGreenOnSuccess(builder, "Extended Validation", report.getExtendedValidation());
                }
                if (report.getCertificateTransparency() != null) {
                    prettyAppendGreenYellow(builder, "Certificate Transparency", report.getCertificateTransparency());
                }
                if (report.getOcspMustStaple() != null) {
                    prettyAppend(builder, "OCSP must Staple", report.getOcspMustStaple());
                }
                if (report.getCrlSupported() != null) {
                    prettyAppendGreenOnSuccess(builder, "CRL Supported", report.getCrlSupported());
                }
                if (report.getOcspSupported() != null) {
                    prettyAppendGreenYellow(builder, "OCSP Supported", report.getOcspSupported());
                }
                if (report.getRevoked() != null) {
                    prettyAppendRedGreen(builder, "Is Revoked", report.getRevoked());
                }
                if (report.getDnsCAA() != null) {
                    prettyAppendGreenOnSuccess(builder, "DNS CCA", report.getDnsCAA());
                }
                if (report.getTrusted() != null) {
                    prettyAppendGreenOnSuccess(builder, "Trusted", report.getTrusted());
                }
                if (report.getRocaVulnerable() != null) {
                    prettyAppendRedGreen(builder, "ROCA (simple)", report.getRocaVulnerable());
                } else {
                    builder.append("ROCA (simple): not tested");
                }
            }
            prettyAppendHeading(builder, "Certificate Checks");
            prettyAppendRedOnSuccess(builder, "Expired Certificates", report.getCertificateExpired());
            prettyAppendRedOnSuccess(builder, "Not yet Valid Certificates", report.getCertificateNotYetValid());
            prettyAppendRedOnSuccess(builder, "Weak Hash Algorithms", report.getCertificateHasWeakHashAlgorithm());
            prettyAppendRedOnSuccess(builder, "Weak Signature Algorithms ", report.getCertificateHasWeakSignAlgorithm());
            prettyAppendRedOnFailure(builder, "Matches Domain", report.getCertificateMachtesDomainName());
            prettyAppendGreenOnSuccess(builder, "Only Trusted", report.getCertificateIsTrusted());
            prettyAppendRedOnFailure(builder, "Contains Blacklisted", report.getCertificateKeyIsBlacklisted());
        }
        return builder;
    }

    private StringBuilder appendSession(StringBuilder builder) {
        prettyAppendHeading(builder, "Session");
        prettyAppendGreenYellow(builder, "Supports Session resumption", report.getSupportsSessionIds());
        prettyAppendGreenYellow(builder, "Supports Session Tickets", report.getSupportsSessionTicket());
        prettyAppend(builder, "Session Ticket Hint", report.getSessionTicketLengthHint());
        prettyAppendYellowOnFailure(builder, "Session Ticket Rotation", report.getSessionTicketGetsRotated());
        prettyAppendRedOnFailure(builder, "Ticketbleed", report.getVulnerableTicketBleed());
        return builder;
    }

    private StringBuilder appendGcm(StringBuilder builder) {
        prettyAppendHeading(builder, "GCM");
        prettyAppendRedOnFailure(builder, "GCM Nonce reuse", report.getGcmReuse());
        if (null == report.getGcmPattern()) {
            prettyAppend(builder, "GCM Pattern");
        } else {
            switch (report.getGcmPattern()) {
                case AKWARD:
                    prettyAppendYellow(builder, addIndentations("GCM Pattern") + report.getGcmPattern().name());
                    break;
                case INCREMENTING:
                case RANDOM:
                    prettyAppendGreen(builder, addIndentations("GCM Pattern") + report.getGcmPattern().name());
                    break;
                case REPEATING:
                    prettyAppendRed(builder, addIndentations("GCM Pattern") + report.getGcmPattern().name());
                    break;
                default:
                    prettyAppend(builder, addIndentations("GCM Pattern") + report.getGcmPattern().name());
                    break;
            }
        }
        prettyAppendRedOnFailure(builder, "GCM Check", report.getGcmCheck());
        return builder;
    }

    private StringBuilder appendIntolerances(StringBuilder builder) {
        prettyAppendHeading(builder, "Common Bugs [EXPERIMENTAL]");
        prettyAppendRedGreen(builder, "Version Intolerant", report.getVersionIntolerance());
        prettyAppendRedGreen(builder, "Ciphersuite Intolerant", report.getCipherSuiteIntolerance());
        prettyAppendRedGreen(builder, "Extension Intolerant", report.getExtensionIntolerance());
        prettyAppendRedGreen(builder, "CS Length Intolerant (>512 Byte)", report.getCipherSuiteLengthIntolerance512());
        prettyAppendRedGreen(builder, "Compression Intolerant", report.getCompressionIntolerance());
        prettyAppendRedGreen(builder, "ALPN Intolerant", report.getAlpnIntolerance());
        prettyAppendRedGreen(builder, "CH Length Intolerant", report.getClientHelloLengthIntolerance());
        prettyAppendRedGreen(builder, "NamedGroup Intolerant", report.getNamedGroupIntolerant());
        prettyAppendRedGreen(builder, "Empty last Extension Intolerant", report.getEmptyLastExtensionIntolerance());
        prettyAppendRedGreen(builder, "SigHashAlgo Intolerant", report.getNamedSignatureAndHashAlgorithmIntolerance());
        prettyAppendRedGreen(builder, "Big ClientHello Intolerant", report.getMaxLengthClientHelloIntolerant());
        prettyAppendRedGreen(builder, "2nd Ciphersuite Byte Bug", report.getOnlySecondCiphersuiteByteEvaluated());
        prettyAppendRedGreen(builder, "Ignores offered Ciphersuites", report.getIgnoresCipherSuiteOffering());
        prettyAppendRedGreen(builder, "Reflects offered Ciphersuites", report.getReflectsCipherSuiteOffering());
        prettyAppendRedGreen(builder, "Ignores offered NamedGroups", report.getIgnoresOfferedNamedGroups());
        prettyAppendRedGreen(builder, "Ignores offered SigHashAlgos", report.getIgnoresOfferedSignatureAndHashAlgorithms());
        return builder;
    }

    private StringBuilder appendAttackVulnerabilities(StringBuilder builder) {
        prettyAppendHeading(builder, "Attack Vulnerabilities");
        prettyAppendRedGreen(builder, "Padding Oracle", report.getPaddingOracleVulnerable());
        prettyAppendRedGreen(builder, "Bleichenbacher", report.getBleichenbacherVulnerable());
        prettyAppendRedGreen(builder, "CRIME", report.getCrimeVulnerable());
        prettyAppendRedGreen(builder, "Breach", report.getBreachVulnerable());
        prettyAppendRedGreen(builder, "Invalid Curve", report.getInvalidCurveVulnerable());
        prettyAppendRedGreen(builder, "Invalid Curve Ephemerals", report.getInvalidCurveEphermaralVulnerable());
        prettyAppendRedGreen(builder, "SSL Poodle", report.getPoodleVulnerable());
        prettyAppendRedGreen(builder, "TLS Poodle", report.getTlsPoodleVulnerable());
        prettyAppendRedGreen(builder, "CVE-20162107", report.getCve20162107Vulnerable());
        prettyAppendRedGreen(builder, "Logjam", report.getLogjamVulnerable());
        prettyAppendRedGreen(builder, "Sweet 32", report.getSweet32Vulnerable());
        prettyAppendDrown(builder, "DROWN", report.getDrownVulnerable());
        prettyAppendRedGreen(builder, "Heartbleed", report.getHeartbleedVulnerable());
        prettyAppendEarlyCcs(builder, "EarlyCcs", report.getEarlyCcsVulnerable());
        return builder;
    }

    private StringBuilder appendPaddingOracleResults(StringBuilder builder) {
        prettyAppendHeading(builder, "PaddingOracle Details");
        if (report.getPaddingOracleTestResultList() == null || report.getPaddingOracleTestResultList().isEmpty()) {
            prettyAppend(builder, "No Testresults");
        } else {
            for (PaddingOracleTestResult testResult : report.getPaddingOracleTestResultList()) {
                String resultString = "" + padToLength(testResult.getSuite().name(), 40) + " - " + testResult.getVersion();
                if (testResult.getVulnerable() == null || testResult.isHasScanningError()) {
                    prettyAppendYellow(builder, resultString + "\t # Error during Scan");
                } else if (testResult.getVulnerable() == Boolean.TRUE) {
                    prettyAppendRed(builder, resultString + "\t - " + testResult.getEqualityError() + "  VULNERABLE");
                } else if (testResult.getVulnerable() == Boolean.FALSE) {
                    prettyAppendGreen(builder, resultString + "\t - No Behavior Difference");
                }

                if ((detail == ScannerDetail.DETAILED && testResult.getVulnerable() == Boolean.TRUE) || detail == ScannerDetail.ALL) {
                    if (testResult.getEqualityError() != EqualityError.NONE || detail == ScannerDetail.ALL) {
                        prettyAppendYellow(builder, "Response Map");
                        if (testResult.getResponseMap() != null && testResult.getResponseMap() != null) {
                            for (int i = 0; i < testResult.getResponseMap().size(); i++) {
                                VectorResponse vectorResponse = testResult.getResponseMap().get(i);
                                if (vectorResponse.isErrorDuringHandshake()) {
                                    prettyAppendRed(builder, padToLength("\t" + vectorResponse.getPaddingVector().getName(), 40) + "ERROR");
                                } else if (vectorResponse.isMissingEquivalent()) {
                                    prettyAppendRed(builder, padToLength("\t" + vectorResponse.getPaddingVector().getName(), 40) + vectorResponse.getFingerprint().toHumanReadable());
                                } else if (vectorResponse.isShaky()) {

                                    prettyAppendYellow(builder, padToLength("\t" + vectorResponse.getPaddingVector().getName(), 40) + vectorResponse.getFingerprint().toHumanReadable());
                                    if (testResult.getResponseMapTwo() != null) {
                                        VectorResponse secondRescanResponse = testResult.getResponseMapTwo().get(i);
                                        if (secondRescanResponse != null && secondRescanResponse.getFingerprint() != null) {
                                            prettyAppendYellow(builder, padToLength("\t\t" + secondRescanResponse.getFingerprint().toHumanReadable(), 40));
                                        }
                                        if (testResult.getResponseMapThree() != null) {
                                            VectorResponse thirdRescanResponse = testResult.getResponseMapThree().get(i);
                                            if (thirdRescanResponse != null && thirdRescanResponse.getFingerprint() != null) {
                                                prettyAppendYellow(builder, padToLength("\t\t\t" + thirdRescanResponse.getFingerprint().toHumanReadable(), 40));
                                            }
                                        }
                                    }
                                } else {
                                    prettyAppend(builder, padToLength("\t" + vectorResponse.getPaddingVector().getName(), 40) + vectorResponse.getFingerprint().toHumanReadable());
                                }
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

    private StringBuilder appendBleichenbacherResults(StringBuilder builder) {
        prettyAppendHeading(builder, "Bleichenbacher Details");
        if (report.getBleichenbacherTestResultList() == null || report.getBleichenbacherTestResultList().isEmpty()) {
            prettyAppend(builder, "No Testresults");
        } else {
            for (BleichenbacherTestResult testResult : report.getBleichenbacherTestResultList()) {
                String resultString = "" + padToLength(testResult.getWorkflowType().name(), 40);
                if (testResult.getVulnerable() == Boolean.TRUE) {
                    prettyAppendRed(builder, resultString + "\t - " + testResult.getEqualityError() + "  VULNERABLE");
                } else if (testResult.getVulnerable() == Boolean.FALSE) {
                    prettyAppendGreen(builder, resultString + "\t - No Behavior Difference");
                } else {
                    prettyAppendYellow(builder, resultString + "\t # Error during Scan");
                }

                if (detail == ScannerDetail.DETAILED || detail == ScannerDetail.ALL) {
                    if (testResult.getEqualityError() != EqualityError.NONE || detail == ScannerDetail.ALL) {
                        prettyAppendYellow(builder, "Response Map");
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

    private StringBuilder appendCipherSuites(StringBuilder builder) {
        if (report.getCipherSuites() != null) {
            prettyAppendHeading(builder, "Supported Ciphersuites");
            for (CipherSuite suite : report.getCipherSuites()) {
                prettyPrintCipherSuite(builder, suite);
            }

            for (VersionSuiteListPair versionSuitePair : report.getVersionSuitePairs()) {
                prettyAppendHeading(builder, "Supported in " + versionSuitePair.getVersion());
                for (CipherSuite suite : versionSuitePair.getCiphersuiteList()) {
                    prettyPrintCipherSuite(builder, suite);
                }
            }
            if (report.getSupportedTls13CipherSuites() != null && report.getSupportedTls13CipherSuites().size() > 0) {
                prettyAppendHeading(builder, "Supported in TLS 1.3");
                for (CipherSuite suite : report.getSupportedTls13CipherSuites()) {
                    prettyPrintCipherSuite(builder, suite);
                }
            }
            prettyAppendHeading(builder, "Symmetric Supported");
            prettyAppendRedOnSuccess(builder, "Null", report.getSupportsNullCiphers());
            prettyAppendRedOnSuccess(builder, "Export", report.getSupportsExportCiphers());
            prettyAppendRedOnSuccess(builder, "Anon", report.getSupportsAnonCiphers());
            prettyAppendRedOnSuccess(builder, "DES", report.getSupportsDesCiphers());
            prettyAppendYellowOnSuccess(builder, "SEED", report.getSupportsSeedCiphers());
            prettyAppendYellowOnSuccess(builder, "IDEA", report.getSupportsIdeaCiphers());
            prettyAppendRedOnSuccess(builder, "RC2", report.getSupportsRc2Ciphers());
            prettyAppendRedOnSuccess(builder, "RC4", report.getSupportsRc4Ciphers());
            prettyAppendYellowOnSuccess(builder, "3DES", report.getSupportsTrippleDesCiphers());
            prettyAppend(builder, "AES", report.getSupportsAes());
            prettyAppend(builder, "CAMELLIA", report.getSupportsCamellia());
            prettyAppend(builder, "ARIA", report.getSupportsAria());
            prettyAppendGreenOnSuccess(builder, "CHACHA20 POLY1305", report.getSupportsChacha());

            prettyAppendHeading(builder, "KeyExchange Supported");
            prettyAppendYellowOnSuccess(builder, "RSA", report.getSupportsRsa());
            prettyAppend(builder, "DH", report.getSupportsDh());
            prettyAppend(builder, "ECDH", report.getSupportsEcdh());
            prettyAppendYellowOnSuccess(builder, "GOST", report.getSupportsGost());
            prettyAppend(builder, "SRP", report.getSupportsSrp());
            prettyAppend(builder, "Kerberos", report.getSupportsKerberos());
            prettyAppend(builder, "Plain PSK", report.getSupportsPskPlain());
            prettyAppend(builder, "PSK RSA", report.getSupportsPskRsa());
            prettyAppend(builder, "PSK DHE", report.getSupportsPskDhe());
            prettyAppend(builder, "PSK ECDHE", report.getSupportsPskEcdhe());
            prettyAppendYellowOnSuccess(builder, "Fortezza", report.getSupportsFortezza());
            prettyAppendGreenOnSuccess(builder, "New Hope", report.getSupportsNewHope());
            prettyAppendGreenOnSuccess(builder, "ECMQV", report.getSupportsEcmqv());

            prettyAppendHeading(builder, "Perfect Forward Secrecy");
            prettyAppendGreenOnSuccess(builder, "Supports PFS", report.getSupportsPfsCiphers());
            prettyAppendGreenOnSuccess(builder, "Prefers PFS", report.getPrefersPfsCiphers());
            prettyAppendGreenOnSuccess(builder, "Supports Only PFS", report.getSupportsOnlyPfsCiphers());

            prettyAppendHeading(builder, "Cipher Types Supports");
            prettyAppend(builder, "Stream", report.getSupportsStreamCiphers());
            prettyAppend(builder, "Block", report.getSupportsBlockCiphers());
            prettyAppendGreenYellow(builder, "AEAD", report.getSupportsAeadCiphers());

            prettyAppendHeading(builder, "Ciphersuite General");
            prettyAppendGreenRed(builder, "Enforces Ciphersuite ordering", report.getEnforcesCipherSuiteOrdering());
        }
        return builder;
    }

    private StringBuilder appendProtocolVersions(StringBuilder builder) {
        if (report.getVersions() != null) {
            prettyAppendHeading(builder, "Supported Protocol Versions");
            for (ProtocolVersion version : report.getVersions()) {
                builder.append(version.name()).append("\n");
            }
            prettyAppendHeading(builder, "Versions");
            prettyAppendRedGreen(builder, "SSL 2.0", report.getSupportsSsl2());
            prettyAppendRedGreen(builder, "SSL 3.0", report.getSupportsSsl3());
            prettyAppendYellowOnFailure(builder, "TLS 1.0", report.getSupportsTls10());
            prettyAppendYellowOnFailure(builder, "TLS 1.1", report.getSupportsTls11());
            prettyAppendRedOnFailure(builder, "TLS 1.2", report.getSupportsTls12());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3", report.getSupportsTls13());
            prettyAppendYellowOnSuccess(builder, "TLS 1.3 Draft 14", report.getSupportsTls13Draft14());
            prettyAppendYellowOnSuccess(builder, "TLS 1.3 Draft 15", report.getSupportsTls13Draft15());
            prettyAppendYellowOnSuccess(builder, "TLS 1.3 Draft 16", report.getSupportsTls13Draft16());
            prettyAppendYellowOnSuccess(builder, "TLS 1.3 Draft 17", report.getSupportsTls13Draft17());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 18", report.getSupportsTls13Draft18());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 19", report.getSupportsTls13Draft19());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 20", report.getSupportsTls13Draft20());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 21", report.getSupportsTls13Draft21());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 22", report.getSupportsTls13Draft22());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 23", report.getSupportsTls13Draft23());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 24", report.getSupportsTls13Draft24());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 25", report.getSupportsTls13Draft25());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 26", report.getSupportsTls13Draft26());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 27", report.getSupportsTls13Draft27());
            prettyAppendGreenOnSuccess(builder, "TLS 1.3 Draft 28", report.getSupportsTls13Draft28());
        }
        return builder;
    }

    private StringBuilder appendHttps(StringBuilder builder) {
        if (report.getSpeaksHttps() == Boolean.TRUE) {
            prettyAppendHeading(builder, "HSTS");
            if (report.getSupportsHsts() == Boolean.TRUE) {
                prettyAppendGreenOnSuccess(builder, "HSTS", report.getSupportsHsts());
                prettyAppendGreenOnSuccess(builder, "HSTS Preloading", report.getSupportsHstsPreloading());
                prettyAppend(builder, "max-age (seconds)", (long) report.getHstsMaxAge());
            } else {
                prettyAppend(builder, "Not supported");
            }
            prettyAppendHeading(builder, "HPKP");
            if (report.getSupportsHpkp() == Boolean.TRUE || report.getSupportsHpkpReportOnly() == Boolean.TRUE) {
                prettyAppendGreenOnSuccess(builder, "HPKP", report.getSupportsHpkp());
                prettyAppendGreenOnSuccess(builder, "HPKP (report only)", report.getSupportsHpkpReportOnly());
                prettyAppend(builder, "max-age (seconds)", (long) report.getHpkpMaxAge());
                if (report.getNormalHpkpPins().size() > 0) {
                    prettyAppend(builder, "");
                    prettyAppendGreen(builder, "HPKP-Pins:");
                    for (HpkpPin pin : report.getNormalHpkpPins()) {
                        prettyAppend(builder, pin.toString());
                    }
                }
                if (report.getReportOnlyHpkpPins().size() > 0) {
                    prettyAppend(builder, "");
                    prettyAppendGreen(builder, "Report Only HPKP-Pins:");
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
        prettyAppendGreenRed(builder, "Secure Renegotiation", report.getSupportsSecureRenegotiation());
        prettyAppendGreenOnSuccess(builder, "Extended Master Secret", report.getSupportsExtendedMasterSecret());
        prettyAppendGreenOnSuccess(builder, "Encrypt Then Mac", report.getSupportsEncryptThenMacSecret());
        prettyAppendGreenOnSuccess(builder, "Tokenbinding", report.getSupportsTokenbinding());

        if (report.getSupportsTokenbinding() == Boolean.TRUE) {
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
        prettyAppendRedGreen(builder, "EC PublicKey reuse", report.getEcPubkeyReuse());
        prettyAppendRedGreen(builder, "DH PublicKey reuse", report.getDhPubkeyReuse());
        prettyAppendRedGreen(builder, "Uses Common DH Primes", report.getUsesCommonDhPrimes());
        if (report.getUsedCommonDhValueList().size() != 0) {
            for (CommonDhValues value : report.getUsedCommonDhValueList()) {
                prettyAppendRed(builder, "\t" + value.getName());
            }
        }
        prettyAppendRedGreen(builder, "Uses Non-Prime Moduli", report.getUsesNonPrimeModuli());
        prettyAppendRedGreen(builder, "Uses Nonsafe-Prime Moduli", report.getUsesNonSafePrimeModuli());
        if (report.getWeakestDhStrength() != null) {
            if (report.getWeakestDhStrength() < 1000) {
                prettyAppendRed(builder, "DH Strength", "" + report.getWeakestDhStrength());
            } else if (report.getWeakestDhStrength() < 2000) {
                prettyAppendYellow(builder, "DH Strength", "" + report.getWeakestDhStrength());
            } else if (report.getWeakestDhStrength() < 4100) {
                prettyAppendGreen(builder, "DH Strength", "" + report.getWeakestDhStrength());
            } else {
                prettyAppendYellow(builder, "DH Strength", "" + report.getWeakestDhStrength());
            }
        }
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

    private StringBuilder prettyAppend(StringBuilder builder, String value) {
        return builder.append(value).append("\n");
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

    private StringBuilder prettyAppendGreenOnSuccess(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColour() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : value)).append("\n");
    }

    private StringBuilder prettyAppendGreenOnFailure(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? value : (report.isNoColour() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendRedOnSuccess(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColour() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : value)).append("\n");
    }

    private StringBuilder prettyAppendRedOnFailure(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? value : (report.isNoColour() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendYellowOnFailure(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? value : (report.isNoColour() == false ? AnsiColors.ANSI_YELLOW : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendYellowOnSuccess(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColour() == false ? AnsiColors.ANSI_YELLOW : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : value)).append("\n");
    }

    private StringBuilder prettyAppendGreenRed(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColour() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : (report.isNoColour() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendRedGreen(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColour() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : (report.isNoColour() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendGreenYellow(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColour() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : (report.isNoColour() == false ? AnsiColors.ANSI_YELLOW : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendYellow(StringBuilder builder, String value) {
        return builder.append((report.isNoColour() == false ? AnsiColors.ANSI_YELLOW : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendRed(StringBuilder builder, String value) {
        return builder.append((report.isNoColour() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendRed(StringBuilder builder, String name, String value) {
        return builder.append(addIndentations(name)).append(": ").append((report.isNoColour() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendGreen(StringBuilder builder, String value) {
        return builder.append((report.isNoColour() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendGreen(StringBuilder builder, String name, String value) {
        return builder.append(addIndentations(name)).append(": ").append((report.isNoColour() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendYellow(StringBuilder builder, String name, String value) {
        return builder.append(addIndentations(name)).append(": ").append((report.isNoColour() == false ? AnsiColors.ANSI_YELLOW : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendHeading(StringBuilder builder, String value) {
        return builder.append((report.isNoColour() == false ? AnsiColors.ANSI_BOLD + AnsiColors.ANSI_BLUE : AnsiColors.ANSI_RESET) + "\n------------------------------------------------------------\n" + value + "\n\n" + AnsiColors.ANSI_RESET);
    }
    
    private StringBuilder prettyAppendUnderlined(StringBuilder builder, String name, String value){
        return builder.append(addIndentations(name)).append(": ").append(AnsiColors.ANSI_UNDERLINE + value + AnsiColors.ANSI_RESET).append("\n");
    }
    
    private StringBuilder prettyAppendUnderlined(StringBuilder builder, String name, boolean value){
        return builder.append(addIndentations(name)).append(": ").append(AnsiColors.ANSI_UNDERLINE + value + AnsiColors.ANSI_RESET).append("\n");
    }
    
    private StringBuilder prettyAppendUnderlined(StringBuilder builder, String name, long value){
        return builder.append(addIndentations(name)).append(": ").append(AnsiColors.ANSI_UNDERLINE + value + AnsiColors.ANSI_RESET).append("\n");
    }
    
    private StringBuilder prettyAppendSubheadingFirst(StringBuilder builder, String name){
        return builder.append((report.isNoColour() == false ? AnsiColors.ANSI_BOLD + AnsiColors.ANSI_PURPLE : AnsiColors.ANSI_RESET) + "\n------------------------------\n" + name + "\n\n" + AnsiColors.ANSI_RESET);
    }
    
    private StringBuilder prettyAppendSubheadingSecond(StringBuilder builder, String name){
        return builder.append((report.isNoColour() == false ? AnsiColors.ANSI_BOLD + AnsiColors.ANSI_CYAN : AnsiColors.ANSI_RESET) + "\n---------------\n" + name + "\n\n" + AnsiColors.ANSI_RESET);
    }

    private void prettyAppendDrown(StringBuilder builder, String testName, DrownVulnerabilityType drownVulnerable) {
        builder.append(addIndentations(testName)).append(": ");
        if (drownVulnerable == null) {
            prettyAppend(builder, "Unknown");
            return;
        }
        switch (drownVulnerable) {
            case FULL:
                prettyAppendRed(builder, "true - fully exploitable");
                break;
            case SSL2:
                prettyAppendRed(builder, "true - SSL 2 supported!");
                break;
            case NONE:
                prettyAppendGreen(builder, "false");
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
                prettyAppendRed(builder, "true - exploitable");
                break;
            case VULN_NOT_EXPLOITABLE:
                prettyAppendRed(builder, "true - probably not exploitable");
                break;
            case NOT_VULNERABLE:
                prettyAppendGreen(builder, "false");
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

    private String padToLength(String value, int length) {
        StringBuilder builder = new StringBuilder(value);
        while (builder.length() < length) {
            builder.append(" ");
        }
        return builder.toString();
    }

    private String addIndentations(String value) {
        StringBuilder builder = new StringBuilder();
        builder.append(value);
        if (value.length() < 8) {
            builder.append("\t\t\t\t ");
        } else if (value.length() < 16) {
            builder.append("\t\t\t ");
        } else if (value.length() < 24) {
            builder.append("\t\t ");
        } else if (value.length() < 32) {
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
        builder.append(addIndentations(testName)).append(": ");
        if (randomEvaluationResult == null) {
            prettyAppend(builder, "Unknown");
            return;
        }
        switch (randomEvaluationResult) {
            case DUPLICATES:
                prettyAppendRed(builder, "true - exploitable");
                break;
            case NOT_ANALYZED:
                prettyAppend(builder, "Not Analyzed");
                break;
            case NOT_RANDOM:
                prettyAppendRed(builder, "Does not seem to be Random");
                break;
            case UNIX_TIME:
                prettyAppend(builder, "Contains UnixTime");
                break;
            case NO_DUPLICATES:
                prettyAppendGreen(builder, "Good");
                break;
        }
    }
}
