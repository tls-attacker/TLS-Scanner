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
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
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
import de.rub.nds.tlsscanner.constants.AnsiColors;
import de.rub.nds.tlsscanner.constants.CipherSuiteGrade;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.ConnectionInsecure;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleTestResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.Date;

public class SiteReportPrinter {

    private static final Logger LOGGER = LogManager.getLogger(SiteReportPrinter.class.getName());

    private final SiteReport report;
    private final ScannerDetail detail;

    private final String hsClientFormat = "%-28s";
    private final String hsVersionFormat = "%-14s";
    private final String hsCiphersuiteFormat = "%-52s";
    private final String hsForwardSecrecyFormat = "%-19s";
    private final String hsKeyLengthFormat = "%-17s";

    public SiteReportPrinter(SiteReport report, ScannerDetail detail) {
        this.report = report;
        this.detail = detail;
    }

    public String getFullReport() {
        StringBuilder builder = new StringBuilder();
        builder.append("Report for ");
        builder.append(report.getHost());
        builder.append("\n");
        if (report.getServerIsAlive() == false) {
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
        appendGcm(builder);
        appendRfc(builder);
        appendCertificate(builder);
        appendSession(builder);
        appendRenegotiation(builder);
        appendHandshakeSimulation(builder);
        appendHttps(builder);
        for (PerformanceData data : report.getPerformanceList()) {
            LOGGER.debug("Type: " + data.getType() + "   Start: " + data.getStarttime() + "    Stop: " + data.getStoptime());
        }
        return builder.toString();
    }

    private StringBuilder appendHandshakeSimulation(StringBuilder builder) {
        if (report.getSimulatedClientList() != null) {
            appendHsNormal(builder);
            if (detail == ScannerDetail.DETAILED) {
                appendHsDetailed(builder);
            } else if (detail == ScannerDetail.ALL) {
                appendHsDetailed(builder);
                appendHsAll(builder);
            }
        }
        return builder;
    }

    private StringBuilder appendHsNormal(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation - Overview");
        prettyAppend(builder, "Tested Clients", Integer.toString(report.getSimulatedClientList().size()));
        String identifier;
        identifier = "Successful Handshakes";
        if (report.getHandshakeSuccessfulCounter() == 0) {
            prettyAppendRed(builder, identifier, Integer.toString(report.getHandshakeSuccessfulCounter()));
        } else {
            prettyAppendGreen(builder, identifier, Integer.toString(report.getHandshakeSuccessfulCounter()));
        }
        identifier = "Failed Handshakes";
        if (report.getHandshakeFailedCounter() == 0) {
            prettyAppendGreen(builder, identifier, Integer.toString(report.getHandshakeFailedCounter()));
        } else {
            prettyAppendRed(builder, identifier, Integer.toString(report.getHandshakeFailedCounter()));
        }
        builder.append("\n");
        identifier = "Secure Connections (RFC 7918)";
        if (report.getConnectionRfc7918SecureCounter() == 0) {
            prettyAppendRed(builder, identifier, Integer.toString(report.getConnectionRfc7918SecureCounter()));
        } else {
            prettyAppendGreen(builder, identifier, Integer.toString(report.getConnectionRfc7918SecureCounter()));
        }
        identifier = "Insecure Connections";
        if (report.getConnectionInsecureCounter() == 0) {
            prettyAppendGreen(builder, identifier, Integer.toString(report.getConnectionInsecureCounter()));
        } else {
            prettyAppendRed(builder, identifier, Integer.toString(report.getConnectionInsecureCounter()));
        }
        prettyAppendHeading(builder, "Handshake Simulation - Default Versions Table");
        prettyAppendHsTable(builder, true);
        return builder;
    }

    private StringBuilder appendHsDetailed(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation - All Versions Table");
        prettyAppendHsTable(builder, false);
        return builder;
    }

    private StringBuilder prettyAppendHsTable(StringBuilder builder, boolean defaultClient) {
        int counter = 0;
        appendHsTableRowHeading(builder, "Client", "Version", "Ciphersuite", "Forward Secrecy", "Server Public Key");
        builder.append("\n");
        if (defaultClient) {
            for (SimulatedClient simulatedClient : report.getSimulatedClientList()) {
                if (simulatedClient.isDefaultVersion()) {
                    if (simulatedClient.getHandshakeSuccessful()) {
                        appendHsTableRowSuccessful(builder, simulatedClient);
                        counter++;
                    } else {
                        appendHsTableRowFailed(builder, simulatedClient);
                        counter++;
                    }
                }
            }
        } else {
            for (SimulatedClient simulatedClient : report.getSimulatedClientList()) {
                if (simulatedClient.getHandshakeSuccessful()) {
                    appendHsTableRowSuccessful(builder, simulatedClient);
                    counter++;
                } else {
                    appendHsTableRowFailed(builder, simulatedClient);
                    counter++;
                }
            }
        }
        if (counter == 0) {
            prettyAppend(builder, "-");
        }
        return builder;
    }

    private StringBuilder appendHsTableRowHeading(StringBuilder builder, String tlsClient, String tlsVersion,
            String ciphersuite, String forwardSecrecy, String keyLength) {
        builder.append(String.format(hsClientFormat, tlsClient));
        builder.append(String.format("| " + hsVersionFormat, tlsVersion));
        builder.append(String.format("| " + hsCiphersuiteFormat, ciphersuite));
        builder.append(String.format("| " + hsForwardSecrecyFormat, forwardSecrecy));
        builder.append(String.format("| " + hsKeyLengthFormat, keyLength));
        builder.append("\n");
        return builder;
    }

    private StringBuilder appendHsTableRowSuccessful(StringBuilder builder, SimulatedClient simulatedClient) {
        String clientName = simulatedClient.getType() + ":" + simulatedClient.getVersion();
        builder.append(getClientColor(clientName, simulatedClient.getConnectionInsecure(), simulatedClient.getConnectionRfc7918Secure()));
        builder.append("| ").append(getProtocolVersionColor(simulatedClient.getSelectedProtocolVersion(), hsVersionFormat));
        builder.append("| ").append(getCipherSuiteColor(simulatedClient.getSelectedCiphersuite(), hsCiphersuiteFormat));
        builder.append("| ").append(getForwardSecrecyColor(simulatedClient.getForwardSecrecy()));
        builder.append("| ").append(getServerPublicKeyParameterColor(simulatedClient));
        builder.append("\n");
        return builder;
    }

    private StringBuilder appendHsTableRowFailed(StringBuilder builder, SimulatedClient simulatedClient) {
        String clientName = simulatedClient.getType() + ":" + simulatedClient.getVersion();
        String row = getProtocolVersionColor(simulatedClient.getSelectedProtocolVersion(), "%s") + ", "
                + getCipherSuiteColor(simulatedClient.getSelectedCiphersuite(), "%s") + ", "
                + getServerPublicKeyParameterColor(simulatedClient);
        builder.append(String.format("%s", getRedString(clientName, hsClientFormat)));
        for (String reason : simulatedClient.getFailReasons()) {
            builder.append(String.format("| %s", getRedString(reason, hsVersionFormat)));
        }
        builder.append("\n");
        builder.append(String.format(hsClientFormat, ""));
        builder.append(String.format("| " + hsVersionFormat, row));
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

    private String getServerPublicKeyParameterColor(SimulatedClient simulatedClient) {
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

    private String getServerPublicKeyParameterToPrint(SimulatedClient simulatedClient) {
        CipherSuite suite = simulatedClient.getSelectedCiphersuite();
        Integer param = simulatedClient.getServerPublicKeyParameter();
        if (suite != null && param != null) {
            if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeRsa()) {
                return param + " bit - rsa";
            } else if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeDh()) {
                return param + " bit - dh";
            } else if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeEcdh()) {
                return param + " bit - ecdh - " + simulatedClient.getSelectedNamedGroup();
            }
        }
        return null;
    }

    private StringBuilder appendHsAll(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation - All Versions Detailed List");
        for (SimulatedClient simulatedClient : report.getSimulatedClientList()) {
            prettyAppendHeading(builder, simulatedClient.getType() + ":" + simulatedClient.getVersion());
            prettyAppendGreenRed(builder, "Handshake Successful", simulatedClient.getHandshakeSuccessful());
            if (!simulatedClient.getHandshakeSuccessful()) {
                for (String reason : simulatedClient.getFailReasons()) {
                    prettyAppend(builder, "", getRedString(reason, "%s"));
                }
            }
            builder.append("\n");
            if (simulatedClient.getConnectionInsecure() != null && simulatedClient.getConnectionInsecure()) {
                prettyAppendRedGreen(builder, "Connection Insecure", simulatedClient.getConnectionInsecure());
                for (String reason : simulatedClient.getInsecureReasons()) {
                    prettyAppend(builder, "", reason);
                }
            }
            prettyAppendGreenRed(builder, "Connection Secure (RFC 7918)", simulatedClient.getConnectionRfc7918Secure());
            builder.append("\n");
            prettyAppend(builder, "Protocol Version Selected", getProtocolVersionColor(simulatedClient.getSelectedProtocolVersion(), "%s"));
            prettyAppend(builder, "Protocol Versions Client", simulatedClient.getSupportedVersionList().toString());
            prettyAppend(builder, "Protocol Versions Server", report.getVersions().toString());
            prettyAppendGreenRed(builder, "Protocol Version is highest", simulatedClient.getHighestPossibleProtocolVersionSeleceted());
            builder.append("\n");
            prettyAppend(builder, "Selected Ciphersuite", getCipherSuiteColor(simulatedClient.getSelectedCiphersuite(), "%s"));
            prettyAppendGreenRed(builder, "Forward Secrecy", simulatedClient.getForwardSecrecy());
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
            prettyAppend(builder, "GCM Pattern", (String) null);
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
        prettyAppendHeading(builder, "PaddingOracle Details");
        if (report.getPaddingOracleTestResultList() == null || report.getPaddingOracleTestResultList().isEmpty()) {
            prettyAppend(builder, "No Testresults");
        } else {
            for (PaddingOracleTestResult testResult : report.getPaddingOracleTestResultList()) {
                String resultString = "" + padToLength(testResult.getSuite().name(), 40) + ":" + testResult.getVersion() + "\t" + testResult.getVectorGeneratorType() + "\t" + testResult.getRecordGeneratorType();
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
                        if (testResult.getResponseMap() != null && testResult.getResponseMap().get(0) != null) {
                            for (ResponseFingerprint fingerprint : testResult.getResponseMap().get(0)) {
                                prettyAppend(builder, "\t" + fingerprint.toString());
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
                builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
            }

            for (VersionSuiteListPair versionSuitePair : report.getVersionSuitePairs()) {
                prettyAppendHeading(builder, "Supported in " + versionSuitePair.getVersion());
                for (CipherSuite suite : versionSuitePair.getCiphersuiteList()) {
                    builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
                }
            }
            if (report.getSupportedTls13CipherSuites() != null && report.getSupportedTls13CipherSuites().size() > 0) {
                prettyAppendHeading(builder, "Supported in TLS13");
                for (CipherSuite suite : report.getSupportedTls13CipherSuites()) {
                    builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
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
            prettyAppendGreenOnSuccess(builder, "AEAD", report.getSupportsAeadCiphers());

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
            //prettyAppend(builder, "DTLS 1.0", report.getSupportsDtls10());
            //prettyAppend(builder, "DTLS 1.2", report.getSupportsDtls10());
            //prettyAppend(builder, "DTLS 1.3", report.getSupportsDtls13());
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
        return (report.isNoColor() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + String.format(format, value == null ? "Unknown" : value) + AnsiColors.ANSI_RESET;
    }

    private String getYellowString(String value, String format) {
        return (report.isNoColor() == false ? AnsiColors.ANSI_YELLOW : AnsiColors.ANSI_RESET) + String.format(format, value == null ? "Unknown" : value) + AnsiColors.ANSI_RESET;
    }

    private String getRedString(String value, String format) {
        return (report.isNoColor() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + String.format(format, value == null ? "Unknown" : value) + AnsiColors.ANSI_RESET;
    }

    private StringBuilder prettyAppend(StringBuilder builder, String value) {
        return builder.append(value == null ? "Unknown" : value).append("\n");
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
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColor() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : value)).append("\n");
    }

    private StringBuilder prettyAppendGreenOnFailure(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? value : (report.isNoColor() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendRedOnSuccess(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColor() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : value)).append("\n");
    }

    private StringBuilder prettyAppendRedOnFailure(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? value : (report.isNoColor() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendYellowOnFailure(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? value : (report.isNoColor() == false ? AnsiColors.ANSI_YELLOW : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendYellowOnSuccess(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColor() == false ? AnsiColors.ANSI_YELLOW : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : value)).append("\n");
    }

    private StringBuilder prettyAppendGreenRed(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColor() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : (report.isNoColor() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendRedGreen(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColor() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : (report.isNoColor() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendGreenYellow(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name)).append(": ").append(value == null ? "Unknown" : (value == Boolean.TRUE ? (report.isNoColor() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET : (report.isNoColor() == false ? AnsiColors.ANSI_YELLOW : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET)).append("\n");
    }

    private StringBuilder prettyAppendYellow(StringBuilder builder, String value) {
        return builder.append((report.isNoColor() == false ? AnsiColors.ANSI_YELLOW : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendYellow(StringBuilder builder, String name, String value) {
        return builder.append(addIndentations(name)).append(": ").append((report.isNoColor() == false ? AnsiColors.ANSI_YELLOW : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendRed(StringBuilder builder, String value) {
        return builder.append((report.isNoColor() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendRed(StringBuilder builder, String name, String value) {
        return builder.append(addIndentations(name)).append(": ").append((report.isNoColor() == false ? AnsiColors.ANSI_RED : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendGreen(StringBuilder builder, String value) {
        return builder.append((report.isNoColor() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendGreen(StringBuilder builder, String name, String value) {
        return builder.append(addIndentations(name)).append(": ").append((report.isNoColor() == false ? AnsiColors.ANSI_GREEN : AnsiColors.ANSI_RESET) + value + AnsiColors.ANSI_RESET).append("\n");
    }

    private StringBuilder prettyAppendHeading(StringBuilder builder, String value) {
        return builder.append((report.isNoColor() == false ? AnsiColors.ANSI_BOLD + AnsiColors.ANSI_BLUE : AnsiColors.ANSI_RESET) + "\n--------------------------------------------------------\n" + value + "\n\n" + AnsiColors.ANSI_RESET);
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
}
