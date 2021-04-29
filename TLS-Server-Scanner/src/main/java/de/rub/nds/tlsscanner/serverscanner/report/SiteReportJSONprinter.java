package de.rub.nds.tlsscanner.serverscanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateType;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowType;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.serverscanner.constants.AnsiColor;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateIssue;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.HandshakeFailureReasons;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.InvalidCurveResponse;
import de.rub.nds.tlsscanner.serverscanner.probe.namedcurve.NamedCurveWitness;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.PaddingOracleStrength;
import de.rub.nds.tlsscanner.serverscanner.rating.*;
import de.rub.nds.tlsscanner.serverscanner.report.after.prime.CommonDhValues;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.report.result.bleichenbacher.BleichenbacherTestResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.cca.CcaTestResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.serverscanner.report.result.ocsp.OcspCertificateResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.raccoonattack.RaccoonAttackProbabilities;
import de.rub.nds.tlsscanner.serverscanner.report.result.raccoonattack.RaccoonAttackPskProbabilities;
import de.rub.nds.tlsscanner.serverscanner.report.result.statistics.RandomEvaluationResult;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.ResponseCounter;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.VectorContainer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.Duration;
import org.joda.time.Period;
import org.joda.time.format.PeriodFormat;

import javax.xml.bind.JAXBException;
import java.math.BigDecimal;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class SiteReportJSONprinter {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SiteReport report;
    private final ScannerDetail detail;
    private final ObjectMapper mapper;
    private int depth;

    public SiteReportJSONprinter(SiteReport report, ScannerDetail detail) {
        this.report = report;
        this.detail = detail;
        mapper = new ObjectMapper();
        this.depth = 0;
    }

    public ObjectNode getJSONReport() {
        ObjectNode jsonReport = mapper.createObjectNode();
        jsonReport.put("hostname", report.getHost());
        if (report.getServerIsAlive() == Boolean.FALSE) {
            jsonReport.put("response", "Cannot reach the Server. Is it online?");
        } else if (report.getSupportsSslTls() == Boolean.FALSE) {
            jsonReport.put("response", "Server does not seem to support SSL / TLS on the scanned port");
        }

        appendProtocolVersions(jsonReport);
        appendCipherSuites(jsonReport);
        appendExtensions(jsonReport);
        appendCompressions(jsonReport);
        appendEcPointFormats(jsonReport);
        appendIntolerances(jsonReport);
        appendAttackVulnerabilities(jsonReport);
        appendBleichenbacherResults(jsonReport);
        appendPaddingOracleResults(jsonReport);
        sessionTicketZeroKeyDetails(jsonReport);
        appendDirectRaccoonResults(jsonReport);
        appendInvalidCurveResults(jsonReport);
        appendRaccoonAttackDetails(jsonReport);
        // appendGcm(builder);
        // appendRfc(builder);
        appendCertificates(jsonReport);
        appendOcsp(jsonReport);
        appendSession(jsonReport);
        appendRenegotiation(jsonReport);
        appendHandshakeSimulation(jsonReport);
        appendHttps(jsonReport);
        appendRandom(jsonReport);
        appendPublicKeyIssues(jsonReport);
        appendClientAuthentication(jsonReport);
        appendScoringResults(jsonReport);
        appendRecommendations(jsonReport);
        appendPerformanceData(jsonReport);

        return jsonReport;
    }

    private void appendDirectRaccoonResults(ObjectNode jsonReport) {
        // TODO this recopying is weired
        List<InformationLeakTest> informationLeakTestList = new LinkedList<>();
        if (report.getDirectRaccoonResultList() == null) {
            return;
        }
        informationLeakTestList.addAll(report.getDirectRaccoonResultList());
        appendInformationLeakTestList(jsonReport, informationLeakTestList, "directRaccoonResults");
    }

    public ObjectNode appendHandshakeSimulation(ObjectNode jsonReport) {
        if (report.getSimulatedClientList() != null) {
            appendHsNormal(jsonReport);
            if (detail == ScannerDetail.DETAILED) {
                appendHandshakeSimulationTable(jsonReport);
            } else if (detail == ScannerDetail.ALL) {
                appendHandshakeSimulationTable(jsonReport);
                appendHandshakeSimulationDetails(jsonReport);
            }
        }
        return jsonReport;
    }

    public ObjectNode appendHsNormal(ObjectNode jsonReport) {
        ObjectNode handShakeSimulationOverview = mapper.createObjectNode();
        handShakeSimulationOverview.put("Tested Clients", Integer.toString(report.getSimulatedClientList().size()));
        handShakeSimulationOverview.put("Handshakes - Successful", Integer.toString(report.getHandshakeSuccessfulCounter()));
        handShakeSimulationOverview.put("Handshakes - Failed", Integer.toString(report.getHandshakeFailedCounter()));
        jsonReport.set("handShakeSimulationOverview", handShakeSimulationOverview);
        return jsonReport;
    }

    public ObjectNode appendHandshakeSimulationTable(ObjectNode jsonReport) {
        ArrayNode handShakeSimulation = jsonReport.putArray("handShakeSimulation");
        for (SimulatedClientResult simulatedClient : report.getSimulatedClientList()) {
            ObjectNode simulatedClientNode = mapper.createObjectNode();
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || simulatedClient.getTlsClientConfig().isDefaultVersion()) {
                String clientName = simulatedClient.getTlsClientConfig().getType() + ":"
                        + simulatedClient.getTlsClientConfig().getVersion();

                simulatedClientNode.put("Client", clientName);
                simulatedClientNode.put("Version", simulatedClient.getSelectedProtocolVersion().name());
                simulatedClientNode.put("Ciphersuite", simulatedClient.getSelectedCipherSuite().name());
                simulatedClientNode.put("Forward Secrecy", simulatedClient.getForwardSecrecy());
                simulatedClientNode.put("Server Public Key", getServerPublicKeyParameterToPrint(simulatedClient));
                handShakeSimulation.add(simulatedClientNode);
            }
        }
        return jsonReport;
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

    public ObjectNode appendHandshakeSimulationDetails(ObjectNode jsonReport) {
        ArrayNode handShaleSimulationDetails = jsonReport.putArray("handShaleSimulationDetailed");
        for (SimulatedClientResult simulatedClient : report.getSimulatedClientList()) {
            ObjectNode simulatedCientNode = mapper.createObjectNode();
            simulatedCientNode.put("type", simulatedClient.getTlsClientConfig().getType());
            simulatedCientNode.put("version", simulatedClient.getTlsClientConfig().getVersion());
            simulatedCientNode.put("Handshake Successful", simulatedClient.getHandshakeSuccessful());
            if (!simulatedClient.getHandshakeSuccessful()) {
                ArrayNode failure = simulatedCientNode.putArray("failureReasons");
                for (HandshakeFailureReasons failureReason : simulatedClient.getFailReasons()) {
                    failure.add(failureReason.getReason());
                }
            }

            if (simulatedClient.getConnectionInsecure() != null && simulatedClient.getConnectionInsecure()) {
                simulatedCientNode.put("Connection Insecure", simulatedClient.getConnectionInsecure());
                ArrayNode failure = simulatedCientNode.putArray("insecureReasons");
                for (String reason : simulatedClient.getInsecureReasons()) {
                    failure.add(reason);
                }
            }
            simulatedCientNode.put("Connection Secure (RFC 7918)", simulatedClient.getConnectionRfc7918Secure());

            simulatedCientNode.put("Protocol Version Selected", simulatedClient.getSelectedProtocolVersion().name());
            simulatedCientNode.put("Protocol Versions Client", simulatedClient.getSupportedVersionList().toString());
            simulatedCientNode.put("Protocol Versions Server", report.getVersions().toString());
            simulatedCientNode.put("Protocol Version is highest",
                    simulatedClient.getHighestPossibleProtocolVersionSelected());
            simulatedCientNode.put("Selected Ciphersuite",
                    simulatedClient.getSelectedCipherSuite().name());
            simulatedCientNode.put("Forward Secrecy", simulatedClient.getForwardSecrecy());
            simulatedCientNode.put("Server Public Key", getServerPublicKeyParameterToPrint(simulatedClient));
            if (simulatedClient.getSelectedCompressionMethod() != null) {
                simulatedCientNode.put("Selected Compression Method", simulatedClient.getSelectedCompressionMethod()
                        .toString());
            } else {
                String tmp = null;
                simulatedCientNode.put("Selected Compression Method", tmp);
            }
            simulatedCientNode.put("Negotiated Extensions", simulatedClient.getNegotiatedExtensions());
            simulatedCientNode.put("Alpn Protocols", (BigDecimal) simulatedClient.getAlpnAnnouncedProtocols());
        }
        return jsonReport;
    }

    public ObjectNode appendRenegotiation(ObjectNode jsonReport) {
        ObjectNode renegotioation = mapper.createObjectNode();
        renegotioation.put("Secure (Extension)", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION)));
        renegotioation.put("Secure (CipherSuite)", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE)));
        renegotioation.put("Insecure", String.valueOf(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION));
        jsonReport.set("renegotioation", renegotioation);
        return jsonReport;
    }

    public ObjectNode appendCertificates(ObjectNode jsonReport) {
        int certCtr = 1;
        if (report.getCertificateChainList() != null && report.getCertificateChainList().isEmpty() == false) {
            for (CertificateChain chain : report.getCertificateChainList()) {
                appendCertificate(jsonReport, chain);
                certCtr++;
            }
        }
        return jsonReport;
    }

    private ObjectNode appendCertificate(ObjectNode jsonReport, CertificateChain chain) {
        ObjectNode certificateChain = mapper.createObjectNode();
        certificateChain.put("Chain ordered", chain.getChainIsOrdered());
        certificateChain.put("Contains Trust Anchor", chain.getContainsTrustAnchor());
        certificateChain.put("Generally Trusted", chain.getGenerallyTrusted());
        jsonReport.set("certificateChainDetails", certificateChain);
        if (chain.getCertificateIssues().size() > 0) {
            ArrayNode certificateIssues = jsonReport.putArray("certificateIssues");
            for (CertificateIssue issue : chain.getCertificateIssues()) {
                certificateIssues.add(issue.getHumanReadable());
            }
        }
        if (!chain.getCertificateReportList().isEmpty()) {
            ArrayNode certificateDetails = jsonReport.putArray("certificateDetails");
            for (int i = 0; i < chain.getCertificateReportList().size(); i++) {
                CertificateReport certReport = chain.getCertificateReportList().get(i);
                ObjectNode cert = mapper.createObjectNode();
                cert.put("Certificate #", (i + 1));

                if (certReport.getSubject() != null) {
                    cert.put("Subject", certReport.getSubject());
                }

                if (certReport.getIssuer() != null) {
                    cert.put("Issuer", certReport.getIssuer());
                }
                if (certReport.getValidFrom() != null) {
                    if (certReport.getValidFrom().before(new Date())) {
                        cert.put("Valid From", certReport.getValidFrom().toString());
                    } else {
                        cert.put("Valid From", certReport.getValidFrom().toString() + " - NOT YET VALID");
                    }
                }
                if (certReport.getValidTo() != null) {
                    if (certReport.getValidTo().after(new Date())) {
                        cert.put("Valid Till", certReport.getValidTo().toString());
                    } else {
                        cert.put("Valid Till", certReport.getValidTo().toString() + " - EXPIRED");
                    }

                }
                if (certReport.getValidFrom() != null && certReport.getValidTo() != null
                        && certReport.getValidTo().after(new Date())) {
                    long time = certReport.getValidTo().getTime() - System.currentTimeMillis();
                    long days = TimeUnit.MILLISECONDS.toDays(time);
                    if (days < 1) {
                        cert.put("Expires in", "<1 day! This certificate expires very soon");
                    } else if (days < 3) {
                        cert.put("Expires in", days + " days! This certificate expires soon");
                    } else if (days < 14) {
                        cert.put("Expires in", days + " days. This certificate expires soon");
                    } else if (days < 31) {
                        cert.put("Expires in", days + " days.");
                    } else if (days < 730) {
                        cert.put("Expires in", days + " days.");
                    } else if (Objects.equals(certReport.getLeafCertificate(), Boolean.TRUE)) {
                        cert.put("Expires in", days
                                + " days. This is usually too long for a leaf certificate");
                    } else {
                        cert.put("Expires in", days / 365 + " years");
                    }
                }
                if (certReport.getPublicKey() != null) {
                    cert.put("PublicKey", certReport.getPublicKey().toString());
                }
                if (certReport.getWeakDebianKey() != null) {
                    cert.put("Weak Debian Key", certReport.getWeakDebianKey());
                }
                if (certReport.getSignatureAndHashAlgorithm() != null) {
                    cert.put("Signature Algorithm", certReport.getSignatureAndHashAlgorithm()
                            .getSignatureAlgorithm().name());
                }
                if (certReport.getSignatureAndHashAlgorithm() != null) {
                    if (certReport.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.SHA1
                            || certReport.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.MD5) {
                        if (!certReport.isTrustAnchor() && !certReport.getSelfSigned()) {
                            cert.put("Hash Algorithm", certReport.getSignatureAndHashAlgorithm()
                                    .getHashAlgorithm().name());
                        } else {
                            cert.put("Hash Algorithm", certReport.getSignatureAndHashAlgorithm()
                                    .getHashAlgorithm().name()
                                    + " - Not critical");
                        }
                    } else {
                        cert.put("Hash Algorithm", certReport.getSignatureAndHashAlgorithm()
                                .getHashAlgorithm().name());
                    }
                }
                if (certReport.getExtendedValidation() != null) {
                    cert.put("Extended Validation", certReport.getExtendedValidation());
                }
                if (certReport.getCertificateTransparency() != null) {
                    cert.put("Certificate Transparency", certReport.getCertificateTransparency());
                }

                if (certReport.getCrlSupported() != null) {
                    cert.put("CRL Supported", certReport.getCrlSupported());
                }
                if (certReport.getOcspSupported() != null) {
                    cert.put("OCSP Supported", certReport.getOcspSupported());
                }
                if (certReport.getOcspMustStaple() != null) {
                    cert.put("OCSP must Staple", certReport.getOcspMustStaple());
                }
                if (certReport.getRevoked() != null) {
                    cert.put("RevocationStatus", certReport.getRevoked());
                }
                if (certReport.getDnsCAA() != null) {
                    cert.put("DNS CCA", certReport.getDnsCAA());
                }
                if (certReport.getRocaVulnerable() != null) {
                    cert.put("ROCA (simple)", certReport.getRocaVulnerable());
                }
                cert.put("Fingerprint (SHA256)", certReport.getSHA256Fingerprint());
                certificateDetails.add(cert);
            }
        }
        return jsonReport;
    }

    private ObjectNode appendOcsp(ObjectNode jsonReport) {
        appendOcspOverview(jsonReport);
        if (report.getOcspResults() != null) {
            int certCtr = 1;
            ObjectNode OCSP = (ObjectNode) jsonReport.get("OCSP");
            ArrayNode OCSPResponse = OCSP.putArray("OCSPResponse");
            for (OcspCertificateResult result : report.getOcspResults()) {
                ObjectNode ocspCert = appendOcspForCertificate(result, certCtr);
                OCSPResponse.add(ocspCert);
                certCtr++;
            }
        }

        return jsonReport;
    }

    private ObjectNode appendOcspOverview(ObjectNode jsonReport) {
        ObjectNode ocsp = mapper.createObjectNode();
        ocsp.put("Supports OCSP ", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_OCSP)));
        // In case extension probe & OCSP probe differ, report stapling as
        // unreliable.
        if (report.getResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST) == TestResult.TRUE
                && report.getResult(AnalyzedProperty.SUPPORTS_OCSP_STAPLING) == TestResult.FALSE) {
            ocsp.put("OCSPStapling", "OCSP Stapling is unreliable on this server.Extension scan reported OCSP Stapling support, but OCSP scan does not.The results are likely incomplete. Maybe rescan for more information?");
            report.putResult(AnalyzedProperty.STAPLING_UNRELIABLE, TestResult.TRUE);
        } else if (report.getResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST) == TestResult.FALSE
                && report.getResult(AnalyzedProperty.SUPPORTS_OCSP_STAPLING) == TestResult.TRUE) {
            ocsp.put("OCSPStapling", "OCSP Stapling is unreliable on this server.Extension scan reported no OCSP support, but OCSP scan does.");
            report.putResult(AnalyzedProperty.STAPLING_UNRELIABLE, TestResult.TRUE);
        }

        // Print stapling support & 'must-staple'
        if (report.getResult(AnalyzedProperty.STAPLING_UNRELIABLE) == TestResult.TRUE) {
            ocsp.put("OCSP Stapling", "true, but unreliable");
            ocsp.put("Must Staple", String.valueOf(report.getResult(AnalyzedProperty.MUST_STAPLE)));
        } else {
            ocsp.put("OCSP Stapling", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_OCSP_STAPLING)));
            ocsp.put("Must Staple", String.valueOf(report.getResult(AnalyzedProperty.MUST_STAPLE)));
        }

        if (report.getResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13) != TestResult.COULD_NOT_TEST) {
            ocsp.put("OCSP Stapling (TLS 1.3)", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13)));
            ocsp.put("Multi Stapling (TLS 1.3)", String.valueOf(report.getResult(AnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES)));
        }

        if (Boolean.TRUE.equals(report.getResult(AnalyzedProperty.SUPPORTS_NONCE) == TestResult.TRUE)) {
            ocsp.put("Nonce Mismatch / Cached Nonce", String.valueOf(report.getResult(AnalyzedProperty.NONCE_MISMATCH)));
        }

        // Is stapling supported, but a CertificateStatus message is missing?
        if (report.getResult(AnalyzedProperty.SUPPORTS_OCSP_STAPLING) == TestResult.TRUE) {
            ocsp.put("Includes Stapled Response", String.valueOf(report.getResult(AnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE)));
            ocsp.put("Stapled Response Expired", String.valueOf(report.getResult(AnalyzedProperty.STAPLED_RESPONSE_EXPIRED)));
        }

        // Are nonces used? If so, do they match?
        ocsp.put("Supports Nonce", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_NONCE)));
        if (Boolean.TRUE.equals(report.getResult(AnalyzedProperty.SUPPORTS_NONCE) == TestResult.TRUE)) {
            ocsp.put("Nonce Mismatch / Cached Nonce", String.valueOf(report.getResult(AnalyzedProperty.NONCE_MISMATCH)));
        }
        jsonReport.set("OCSP", ocsp);
        return jsonReport;
    }

    private ObjectNode appendOcspForCertificate(OcspCertificateResult result, int certNo) {

        ObjectNode ocspDetailed = mapper.createObjectNode();
        ocspDetailed.put("certNumber", "Detailed OCSP results for certificate " + certNo + " of "
                + report.getOcspResults().size());
        if (result.isSupportsStapling()) {
            if (result.getStapledResponse() != null) {
                ocspDetailed.put("Includes Stapled Response", true);
                if (result.getFirstResponse().getResponseStatus() == 0) {
                    long differenceHoursStapled = result.getDifferenceHoursStapled();
                    if (differenceHoursStapled < 24) {
                        ocspDetailed.put("Stapled Response Cached", differenceHoursStapled + " hours");
                    } else {
                        ocspDetailed.put("Stapled Response Cached", differenceHoursStapled / 24 + " days");
                    }
                    ocspDetailed.put("Stapled Response Expired", result.isStapledResponseExpired());
                }
                ocspDetailed.put("Supports Stapled Nonce", result.isSupportsStapledNonce());
            } else {
                ocspDetailed.put("Includes Stapled Response", false);
            }
        }

        ocspDetailed.put("Supports Nonce", result.isSupportsNonce());
        ocspDetailed.put("Nonce Mismatch / Cached Nonce", result.isNonceMismatch());

        if (result.getStapledResponse() != null) {
            if (result.getStapledResponse().getResponseStatus() > 0) {
                ocspDetailed.put("Stapled OCSP Response", "Server stapled an erroneous OCSP response");
            }
            ocspDetailed.put("Stapled OCSP Response", result.getStapledResponse().toString(false));
        }

        if (result.getFirstResponse() != null) {
            if (result.getFirstResponse().getResponseStatus() > 0) {
                ocspDetailed.put("Requested OCSP Response (HTTP POST)", "OCSP Request was not accepted by the OCSP Responder");

                // Check if certificate chain was unordered. This will make the
                // request fail very likely.
                CertificateChain chain = result.getCertificate();
                if (Boolean.FALSE.equals(chain.getChainIsOrdered())) {
                    ocspDetailed.put("reason",
                            "This likely happened due the certificate chain being unordered. This is not supported yet by this scan");
                }
                ocspDetailed.put("Requested OCSP Response (HTTP POST)", result.getFirstResponse().toString(false));
            }
        } else if (result.getFirstResponse() == null && result.getHttpGetResponse() != null) {
            ocspDetailed.put("Requested OCSP Response (HTTP POST)", "Retrieved an OCSP response via HTTP GET, but not via HTTP POST");
        }

        // Print requested HTTP GET response
        if (result.getHttpGetResponse() != null) {
            ocspDetailed.put("Requested OCSP Response (HTTP GET)", result.getHttpGetResponse().toString(false));
        } else if (result.getHttpGetResponse() == null && result.getFirstResponse() != null) {
            ocspDetailed.put("Requested OCSP Response (HTTP GET)", "Retrieved an OCSP response via HTTP POST, but not via HTTP GET");
        }
        return ocspDetailed;
    }

    public ObjectNode appendSession(ObjectNode jsonReport) {
        ObjectNode session = mapper.createObjectNode();
        session.put("Supports Session resumption", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_SESSION_IDS)));
        session.put("Supports Session Tickets", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_SESSION_TICKETS)));
        session.put("Issues TLS 1.3 Session Tickets", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS)));
        jsonReport.set("session", session);
        return jsonReport;
    }

    public ObjectNode appendIntolerances(ObjectNode jsonReport) {
        ObjectNode commonBugs = mapper.createObjectNode();
        commonBugs.put("Version Intolerant", String.valueOf(report.getResult(AnalyzedProperty.HAS_VERSION_INTOLERANCE)));
        commonBugs.put("Ciphersuite Intolerant", String.valueOf(report.getResult(AnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE)));
        commonBugs.put("Extension Intolerant", String.valueOf(report.getResult(AnalyzedProperty.HAS_EXTENSION_INTOLERANCE)));
        commonBugs.put("CS Length Intolerant (>512 Byte)", String.valueOf(report.getResult(AnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE)));
        commonBugs.put("Compression Intolerant", String.valueOf(report.getResult(AnalyzedProperty.HAS_COMPRESSION_INTOLERANCE)));
        commonBugs.put("ALPN Intolerant", String.valueOf(report.getResult(AnalyzedProperty.HAS_ALPN_INTOLERANCE)));
        commonBugs.put("CH Length Intolerant", String.valueOf(report.getResult(AnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE)));
        commonBugs.put("NamedGroup Intolerant", String.valueOf(report.getResult(AnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE)));
        commonBugs.put("Empty last Extension Intolerant", String.valueOf(report.getResult(AnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE)));
        commonBugs.put("SigHashAlgo Intolerant", String.valueOf(report.getResult(AnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE)));
        commonBugs.put("Big ClientHello Intolerant", String.valueOf(report.getResult(AnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE)));
        commonBugs.put("2nd Ciphersuite Byte Bug", String.valueOf(report.getResult(AnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG)));
        commonBugs.put("Ignores offered Ciphersuites", String.valueOf(report.getResult(AnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES)));
        commonBugs.put("Reflects offered Ciphersuites", String.valueOf(report.getResult(AnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES)));
        commonBugs.put("Ignores offered NamedGroups", String.valueOf(report.getResult(AnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS)));
        commonBugs.put("Ignores offered SigHashAlgos", String.valueOf(report.getResult(AnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS)));
        jsonReport.set("commonBugs", commonBugs);
        return jsonReport;
    }

    public ObjectNode appendAttackVulnerabilities(ObjectNode jsonReport) {
        ObjectNode attackVulnerabilities = mapper.createObjectNode();
        if (report.getKnownVulnerability() == null) {
            attackVulnerabilities.put("Padding Oracle", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE)));
        } else {
            attackVulnerabilities.put("Padding Oracle", "true - " + report.getKnownVulnerability().getShortName());
        }
        attackVulnerabilities.put("Bleichenbacher", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER)));
        attackVulnerabilities.put("Raccoon", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK)));
        attackVulnerabilities.put("Direct Raccoon", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON)));
        attackVulnerabilities.put("CRIME", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_CRIME)));
        attackVulnerabilities.put("Breach", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_BREACH)));
        attackVulnerabilities.put("Invalid Curve", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE)));
        attackVulnerabilities.put("Invalid Curve (ephemeral)", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL)));
        attackVulnerabilities.put("Invalid Curve (twist)", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST)));
        attackVulnerabilities.put("SSL Poodle", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_POODLE)));
        attackVulnerabilities.put("TLS Poodle", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_TLS_POODLE)));
        attackVulnerabilities.put("Logjam", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_LOGJAM)));
        attackVulnerabilities.put("Sweet 32", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_SWEET_32)));
        attackVulnerabilities.put("General DROWN", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN)));
        attackVulnerabilities.put("Extra Clear DROWN", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_EXTRA_CLEAR_DROWN)));
        attackVulnerabilities.put("Heartbleed", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_HEARTBLEED)));
        attackVulnerabilities.put("EarlyCcs", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS)));
        attackVulnerabilities.put("CVE-2020-13777 (Zero key)", String.valueOf(report.getResult(AnalyzedProperty.VULNERABLE_TO_SESSION_TICKET_ZERO_KEY)));
        jsonReport.set("attackVulnerabilities", attackVulnerabilities);
        return jsonReport;
    }

    public ObjectNode appendRaccoonAttackDetails(ObjectNode jsonReport) {
        ObjectNode raccoon = mapper.createObjectNode();
        DecimalFormat decimalFormat = new DecimalFormat();
        decimalFormat.setMaximumFractionDigits(24);
        if ((report.getResult(AnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK) == TestResult.TRUE || detail
                .isGreaterEqualTo(ScannerDetail.DETAILED)) && report.getRaccoonAttackProbabilities() != null) {
            raccoon.put("Available Injection points:", (long) report.getRaccoonAttackProbabilities().size());
            if (report.getRaccoonAttackProbabilities().size() > 0) {
                ArrayNode probabilities = raccoon.putArray("Probabilties");
                for (RaccoonAttackProbabilities probabilbities : report.getRaccoonAttackProbabilities()) {
                    probabilities.add(addIndentations(probabilbities.getPosition().name()) + "\t "
                            + probabilbities.getBitsLeaked() + "\t"
                            + decimalFormat.format(probabilbities.getChanceForEquation()));
                }
                if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                        || report.getResult(AnalyzedProperty.SUPPORTS_PSK_DHE) == TestResult.TRUE) {
                    raccoon.put("PSK Length Probabilties", addIndentations("PSK Length") + addIndentations("Bitleak") + "Probability");

                    for (RaccoonAttackProbabilities probabilbities : report.getRaccoonAttackProbabilities()) {

                        ArrayNode probabilityPosition = raccoon.putArray(probabilbities.getPosition().name());

                        for (RaccoonAttackPskProbabilities pskProbability : probabilbities.getPskProbabilityList()) {
                            probabilityPosition.add(addIndentations("" + pskProbability.getPskLength())
                                    + addIndentations("" + pskProbability.getZeroBitsRequiredToNextBlockBorder())
                                    + decimalFormat.format(pskProbability.getChanceForEquation()));
                        }
                    }
                }

            }
        }
        jsonReport.set("raccoon", raccoon);
        return jsonReport;
    }

    public ObjectNode appendInformationLeakTestList(ObjectNode jsonReport,
                                                    List<InformationLeakTest> informationLeakTestList, String heading) {
        ArrayNode raccoonResultArray = jsonReport.putArray(heading);
        ObjectNode node = mapper.createObjectNode();
        if (informationLeakTestList == null || informationLeakTestList.isEmpty()) {
            node.put("result", "No Testresults");
            raccoonResultArray.add(node);
        } else {
            for (InformationLeakTest testResult : informationLeakTestList) {
                String pValue;
                if (testResult.getValueP() >= 0.001) {
                    pValue = String.format("%.3f", testResult.getValueP());
                } else {
                    pValue = "<0.001";
                }
                String resultString = testResult.getTestInfo().getPrintableName();
                if (testResult.getValueP() < 0.01) {
                    node.put("result",
                            padToLength(resultString, 80) + " | "
                                    + padToLength(testResult.getEqualityError().name(), 25)
                                    + padToLength("| VULNERABLE", 25) + "| P: " + pValue);
                } else if (testResult.getValueP() < 0.05) {
                    node.put("result",
                            padToLength(resultString, 80) + " | "
                                    + padToLength(testResult.getEqualityError().name(), 25)
                                    + padToLength("| PROBABLY VULNERABLE", 25) + "| P: " + pValue);
                } else if (testResult.getValueP() < 1) {
                    node.put("result",
                            padToLength(resultString, 80) + " | " + padToLength("No significant difference", 25)
                                    + padToLength("| NOT VULNERABLE", 25) + "| P: " + pValue);
                } else {
                    node.put("result",
                            padToLength(resultString, 80) + " | " + padToLength("No behavior difference", 25)
                                    + padToLength("| NOT VULNERABLE", 25) + "| P: " + pValue);
                }

                if ((detail == ScannerDetail.DETAILED && Objects.equals(testResult.isSignificantDistinctAnswers(),
                        Boolean.TRUE)) || detail == ScannerDetail.ALL) {
                    if (testResult.getEqualityError() != EqualityError.NONE || detail == ScannerDetail.ALL) {
                        appendInformationLeakTestResult(node, testResult);
                    }
                }
                raccoonResultArray.add(node);
            }

        }
        return jsonReport;
    }


    public ObjectNode appendPaddingOracleResults(ObjectNode jsonReport) {
        try {
            ObjectNode paddingOracle = mapper.createObjectNode();
            if (Objects.equals(report.getResult(AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE), TestResult.TRUE)) {
                if (report.getKnownVulnerability() != null) {
                    KnownPaddingOracleVulnerability knownVulnerability = report.getKnownVulnerability();
                    paddingOracle.put("Identification", knownVulnerability.getLongName());
                    paddingOracle.put("CVE", knownVulnerability.getCve());
                    if (knownVulnerability.getStrength() != PaddingOracleStrength.WEAK) {
                        paddingOracle.put("Strength", knownVulnerability.getStrength().name());
                    } else {
                        paddingOracle.put("Strength", knownVulnerability.getStrength().name());
                    }
                    if (knownVulnerability.isObservable()) {
                        paddingOracle.put("Observable", "" + knownVulnerability.isObservable());
                    } else {
                        paddingOracle.put("Observable", "" + knownVulnerability.isObservable());
                    }
                    paddingOracle.put("Description", knownVulnerability.getDescription());
                    ArrayNode affectedProducts = paddingOracle.putArray("affectedProducts");

                    for (String s : knownVulnerability.getAffectedProducts()) {
                        affectedProducts.add(s);
                    }
                    paddingOracle.put("Suggestion",
                            "If your tested software/hardware is not in this list, please let us know so we can add it here.");
                } else {
                    paddingOracle.put(
                            "Identification",
                            "Could not identify vulnerability. Please contact us if you know which software/hardware is generating this behavior.");
                }
            }
            if (report.getPaddingOracleTestResultList() == null || report.getPaddingOracleTestResultList().isEmpty()) {
                paddingOracle.put("responseMap", "No Testresults");
            } else {
                paddingOracle.put("responseMap", "No vulnerability present to identify");

                // TODO this recopying is weired
                List<InformationLeakTest> informationLeakTestList = new LinkedList<>();
                informationLeakTestList.addAll(report.getPaddingOracleTestResultList());
                appendInformationLeakTestList(paddingOracle, informationLeakTestList, "Padding Oracle Details");
            }
            jsonReport.set("paddingOracle", paddingOracle);
        } catch (Exception E) {
            System.out.println("Exception Occured");
        }
        return jsonReport;
    }


    public ObjectNode appendInformationLeakTestResult(ObjectNode node, InformationLeakTest informationLeakTest) {
        try {
            ResponseFingerprint defaultAnswer = informationLeakTest.retrieveMostCommonAnswer().getFingerprint();
            List<VectorContainer> vectorContainerList = informationLeakTest.getVectorContainerList();
            for (VectorContainer vectorContainer : vectorContainerList) {
                node.put("name", padToLength(vectorContainer.getVector().getName(), 40));
                for (ResponseCounter counter : vectorContainer.getDistinctResponsesCounterList()) {
                    AnsiColor color = AnsiColor.GREEN;
                    if (!counter.getFingerprint().equals(defaultAnswer)) {
                        // TODO received app data should also make this red
                        color = AnsiColor.RED;
                    }
                    node.put("value",
                            padToLength((counter.getFingerprint().toHumanReadable()), 40)
                                    + counter.getCounter() + "/" + counter.getTotal() + " ("
                                    + String.format("%.2f", counter.getProbability() * 100) + "%)");

                }
            }
        } catch (Exception E) {
            LOGGER.error("Error", E.getMessage());
        }
        return node;
    }

    public ObjectNode appendBleichenbacherResults(ObjectNode jsonReport) {
        try {
            ArrayNode bleichenbacherDetails = jsonReport.putArray("bleichenbacherDetails");
            if (report.getBleichenbacherTestResultList() != null || !report.getBleichenbacherTestResultList().isEmpty()) {
                for (BleichenbacherTestResult testResult : report.getBleichenbacherTestResultList()) {
                    ObjectNode bleichenbacher = mapper.createObjectNode();
                    bleichenbacher.put("workflowType", testResult.getWorkflowType().name());
                    bleichenbacher.put("vulnerable", testResult.getVulnerable());

                    if (detail == ScannerDetail.DETAILED || detail == ScannerDetail.ALL) {
                        if (testResult.getEqualityError() != EqualityError.NONE || detail == ScannerDetail.ALL) {
                            ArrayNode bleichenbacherResponseMap = bleichenbacher.putArray("bleichenbacherResponseMap");
                            if (testResult.getVectorFingerPrintPairList() != null
                                    && !testResult.getVectorFingerPrintPairList().isEmpty()) {
                                for (VectorResponse vectorFingerPrintPair : testResult.getVectorFingerPrintPairList()) {
                                    ObjectNode bleichenbacherResponse = mapper.createObjectNode();
                                    bleichenbacherResponse.put(vectorFingerPrintPair.getVector().getName()
                                            , vectorFingerPrintPair.getFingerprint().toHumanReadable());
                                    bleichenbacherResponseMap.add(bleichenbacherResponse);
                                }

                            }
                        }
                    }
                    bleichenbacherDetails.add(bleichenbacher);
                }
            } else {
                bleichenbacherDetails.add("No Testresults");
            }
        } catch (Exception E) {
            System.out.println("Exception Occured");
        }
        return jsonReport;
    }

    public ObjectNode appendEcPointFormats(ObjectNode jsonReport) {
        ObjectNode ellipticCurvePointFormats = mapper.createObjectNode();
        ellipticCurvePointFormats.put("Uncompressed", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT)));
        ellipticCurvePointFormats.put("ANSIX962 Prime", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME)));
        ellipticCurvePointFormats.put("ANSIX962 Char2", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2)));
        ellipticCurvePointFormats.put("TLS 1.3 ANSIX962  SECP", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION)));
        jsonReport.set("ellipticCurvePointFormats", ellipticCurvePointFormats);
        return jsonReport;
    }

    public ObjectNode appendInvalidCurveResults(ObjectNode jsonReport) {
        ObjectNode invalideCurveDetails = mapper.createObjectNode();
        boolean foundCouldNotTest = false;
        if (report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE) == TestResult.NOT_TESTED_YET
                && report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL) == TestResult.NOT_TESTED_YET
                && report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST) == TestResult.NOT_TESTED_YET) {
            invalideCurveDetails.put("result", "Not Tested");
        } else if (report.getInvalidCurveResultList() == null) {
            invalideCurveDetails.put("result", "No Testresults");
        } else if (report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE) == TestResult.FALSE
                && report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL) == TestResult.FALSE
                && report.getResult(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST) == TestResult.FALSE
                && detail != ScannerDetail.ALL) {
            invalideCurveDetails.put("result", "No Vulnerabilities found");
        } else {
            ArrayNode responseDetails = invalideCurveDetails.putArray("responseMap");
            for (InvalidCurveResponse response : report.getInvalidCurveResultList()) {
                ObjectNode invalidCurveResponse = mapper.createObjectNode();
                if (response.getChosenGroupReusesKey() == TestResult.COULD_NOT_TEST
                        || response.getShowsVulnerability() == TestResult.COULD_NOT_TEST
                        || response.getShowsVulnerability() == TestResult.COULD_NOT_TEST) {
                    foundCouldNotTest = true;
                }
                if ((response.getShowsVulnerability() == TestResult.TRUE && detail
                        .isGreaterEqualTo(ScannerDetail.NORMAL))
                        || (response.getShowsPointsAreNotValidated() == TestResult.TRUE && detail
                        .isGreaterEqualTo(ScannerDetail.DETAILED)) || detail == ScannerDetail.ALL) {
                    invalidCurveResponse.put("response", response.getVector().toString());
                    switch (response.getShowsPointsAreNotValidated()) {
                        case TRUE:
                            invalidCurveResponse.put("pointValidation", "Server did not validate points");
                            break;
                        case FALSE:
                            invalidCurveResponse.put("pointValidation", "Server did validate points / uses invulnerable algorithm");
                            break;
                        default:
                            invalidCurveResponse.put("pointValidation", "Could not test point validation");
                            break;
                    }
                    switch (response.getChosenGroupReusesKey()) {
                        case TRUE:
                            invalidCurveResponse.put("keyReuse", "Server did reuse key");
                            break;
                        case FALSE:
                            invalidCurveResponse.put("keyReuse", "Server did not reuse key");
                            break;
                        default:
                            invalidCurveResponse.put("keyReuse", "Could not test key reuse");
                            break;
                    }
                    switch (response.getShowsVulnerability()) {
                        case TRUE:
                            invalidCurveResponse.put("vulnerable", "Server is vulnerable");
                            break;
                        case FALSE:
                            invalidCurveResponse.put("vulnerable", "Server is not vulnerable");
                            break;
                        default:
                            invalidCurveResponse.put("vulnerable", "Could not test for vulnerability");
                            break;
                    }
                    switch (response.getSideChannelSuspected()) {
                        case TRUE:
                            invalidCurveResponse.put("sideChannel", "Side Channel suspected");
                            break;
                        default:
                            invalidCurveResponse.put("sideChannel", "No Side Channel suspected");
                            break;
                    }
                    responseDetails.add(invalidCurveResponse);
                }
            }

            if (foundCouldNotTest && detail.isGreaterEqualTo(ScannerDetail.NORMAL)) {
                invalideCurveDetails.put("couldNotTest", "Some tests did not finish");
            }
        }
        jsonReport.set("invalideCurveDetails", invalideCurveDetails);
        return jsonReport;
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

    public ObjectNode appendCipherSuites(ObjectNode jsonReport) {
        if (report.getCipherSuites() != null) {
            if (!report.getCipherSuites().isEmpty()) {
                ArrayNode supportedCipherSuites = jsonReport.putArray("supportedCipherSuites");
                for (CipherSuite suite : report.getCipherSuites()) {
                    supportedCipherSuites.add(String.valueOf(suite));
                }
            }

            if (report.getVersionSuitePairs() != null && !report.getVersionSuitePairs().isEmpty()) {
                ObjectNode versionPair = mapper.createObjectNode();
                for (VersionSuiteListPair versionSuitePair : report.getVersionSuitePairs()) {
                    ArrayNode arrayNode = versionPair.putArray(toHumanReadable(versionSuitePair.getVersion()));
                    for (CipherSuite suite : versionSuitePair.getCipherSuiteList()) {
                        arrayNode.add(String.valueOf(suite));
                    }
                }
                jsonReport.set("VersionSuiteListPair", versionPair);
            }

            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                ObjectNode symmetricSupported = mapper.createObjectNode();
                symmetricSupported.put("Null", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_NULL_CIPHERS)));
                symmetricSupported.put("Export", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_EXPORT)));
                symmetricSupported.put("Anon", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ANON)));
                symmetricSupported.put("DES", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_DES)));
                symmetricSupported.put("SEED", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_SEED)));
                symmetricSupported.put("IDEA", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_IDEA)));
                symmetricSupported.put("RC2", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_RC2)));
                symmetricSupported.put("RC4", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_RC4)));
                symmetricSupported.put("3DES", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_3DES)));
                symmetricSupported.put("AES", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_AES)));
                symmetricSupported.put("CAMELLIA", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_CAMELLIA)));
                symmetricSupported.put("ARIA", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ARIA)));
                symmetricSupported.put("CHACHA20 POLY1305", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_CHACHA)));
                jsonReport.set("symmetricSupported", symmetricSupported);

                ObjectNode keyExchangeSupported = mapper.createObjectNode();
                keyExchangeSupported.put("RSA", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_RSA)));
                keyExchangeSupported.put("DH", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_DH)));
                keyExchangeSupported.put("ECDH", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ECDH)));
                keyExchangeSupported.put("GOST", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_GOST)));
                // keyExchangeSupported.put("SRP", report.getSupportsSrp());
                keyExchangeSupported.put("Kerberos", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_KERBEROS)));
                keyExchangeSupported.put("Plain PSK", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_PSK_PLAIN)));
                keyExchangeSupported.put("PSK RSA", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_PSK_RSA)));
                keyExchangeSupported.put("PSK DHE", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_PSK_DHE)));
                keyExchangeSupported.put("PSK ECDHE", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_PSK_ECDHE)));
                keyExchangeSupported.put("Fortezza", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_FORTEZZA)));
                keyExchangeSupported.put("New Hope", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_NEWHOPE)));
                keyExchangeSupported.put("ECMQV", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ECMQV)));
                keyExchangeSupported.put("TLS 1.3 PSK_DHE", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS13_PSK_DHE)));
                jsonReport.set("keyExchangeSupported", keyExchangeSupported);

                ObjectNode keyExchangeSignatures = mapper.createObjectNode();
                keyExchangeSignatures.put("RSA", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_RSA_CERT)));
                keyExchangeSignatures.put("ECDSA", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ECDSA)));
                keyExchangeSignatures.put("DSS", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_DSS)));
                jsonReport.set("keyExchangeSignatures", keyExchangeSignatures);

                ObjectNode cipherTypesSupports = mapper.createObjectNode();
                cipherTypesSupports.put("Stream", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_STREAM_CIPHERS)));
                cipherTypesSupports.put("Block", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS)));
                cipherTypesSupports.put("AEAD", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_AEAD)));
                jsonReport.set("cipherTypesSupports", cipherTypesSupports);
            }
            ObjectNode perfectForwardSecrecy = mapper.createObjectNode();
            perfectForwardSecrecy.put("Supports PFS", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_PFS)));
            perfectForwardSecrecy.put("Prefers PFS", String.valueOf(report.getResult(AnalyzedProperty.PREFERS_PFS)));
            perfectForwardSecrecy.put("Supports Only PFS", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ONLY_PFS)));
            jsonReport.set("perfectForwardSecrecy", perfectForwardSecrecy);

            ObjectNode ciphersuiteGeneral = mapper.createObjectNode();
            ciphersuiteGeneral.put("Enforces Ciphersuite ordering", String.valueOf(report.getResult(AnalyzedProperty.ENFORCES_CS_ORDERING)));
            jsonReport.set("ciphersuiteGeneral", ciphersuiteGeneral);

        }
        return jsonReport;
    }

    public ObjectNode appendProtocolVersions(ObjectNode jsonReport) {
        if (report.getVersions() != null) {
            ObjectNode versions = mapper.createObjectNode();
            versions.put("SSL 2.0", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_SSL_2)));
            versions.put("SSL 3.0", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_SSL_3)));
            versions.put("TLS 1.0", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0)));
            versions.put("TLS 1.1", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1)));
            versions.put("TLS 1.2", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2)));
            versions.put("TLS 1.3", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3)));
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 14", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 15", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 16", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 17", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 18", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 19", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 20", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 21", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 22", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 23", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 24", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 25", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 26", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 27", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27)));
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28) == TestResult.TRUE) {
                versions.put("TLS 1.3 Draft 28", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28)));
            }
            jsonReport.set("versions", versions);
        }
        return jsonReport;
    }

    public ObjectNode appendHttps(ObjectNode jsonReport) {
        ObjectNode https = mapper.createObjectNode();
        if (report.getResult(AnalyzedProperty.SUPPORTS_HTTPS) == TestResult.TRUE) {
            try {
                ObjectNode hsts = mapper.createObjectNode();
                ObjectNode hpkp = mapper.createObjectNode();
                if (report.getResult(AnalyzedProperty.SUPPORTS_HSTS) == TestResult.TRUE) {
                    hsts.put("HSTS", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_HSTS)));
                    hsts.put("HSTS Preloading", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_HSTS_PRELOADING)));
                    hsts.put("max-age (seconds)", (long) report.getHstsMaxAge());
                    https.set("HSTS", hsts);
                } else {
                    https.put("HSTS", "Not Supported");
                }
                if (report.getResult(AnalyzedProperty.SUPPORTS_HPKP) == TestResult.TRUE
                        || report.getResult(AnalyzedProperty.SUPPORTS_HPKP_REPORTING) == TestResult.TRUE) {
                    hpkp.put("HPKP", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_HPKP)));
                    hpkp.put("HPKP (report only)", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_HPKP_REPORTING)));
                    hpkp.put("max-age (seconds)", (long) report.getHpkpMaxAge());
                    if (report.getNormalHpkpPins().size() > 0) {
                        ArrayNode hpkpPins = hpkp.putArray("HPKP-Pins");
                        for (HpkpPin pin : report.getNormalHpkpPins()) {
                            hpkpPins.add(pin.toString());
                        }
                    }
                    if (report.getReportOnlyHpkpPins().size() > 0) {
                        ArrayNode hpkpOnlyPins = hpkp.putArray("ReportOnlyHPKP-Pins");
                        for (HpkpPin pin : report.getReportOnlyHpkpPins()) {
                            hpkpOnlyPins.add(pin.toString());
                        }
                    }
                    https.set("HPKP", hpkp);
                } else {
                    https.put("HPKP", "Not Supported");
                }
                ArrayNode HTTPSResponseHeader = https.putArray("HTTPSResponseHeader");
                for (HttpsHeader header : report.getHeaderList()) {
                    HTTPSResponseHeader.add(header.getHeaderName().getValue() + ":" + header.getHeaderValue().getValue());
                }
            } catch (Exception E) {
                System.out.println("Exception Occured" + E.getLocalizedMessage().toString());
            }
        }
        jsonReport.set("HTTPS", https);
        return jsonReport;
    }

    public ObjectNode appendExtensions(ObjectNode jsonReport) {
        if (report.getSupportedExtensions() != null) {
            ArrayNode supportedExtensions = jsonReport.putArray("supportedExtensions");
            for (ExtensionType type : report.getSupportedExtensions()) {
                supportedExtensions.add(type.name());
            }
        }

        ObjectNode extensionDetails = mapper.createObjectNode();
        extensionDetails.put("Secure Renegotiation", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION)));
        extensionDetails.put("Extended Master Secret", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET)));
        extensionDetails.put("Encrypt Then Mac", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC)));
        extensionDetails.put("Tokenbinding", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_TOKENBINDING)));
        extensionDetails.put("Certificate Status Request", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST)));
        extensionDetails.put("Certificate Status Request v2", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2)));
        extensionDetails.put("ESNI", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ESNI)));
        jsonReport.set("Extensions", extensionDetails);

        if (report.getResult(AnalyzedProperty.SUPPORTS_TOKENBINDING) == TestResult.TRUE) {
            ObjectNode tokenBindingVersion = mapper.createObjectNode();
            ArrayNode tokenBinding = tokenBindingVersion.putArray("tokenBindingVersions");
            for (TokenBindingVersion version : report.getSupportedTokenBindingVersion()) {
                tokenBinding.add(version.toString());
            }
            ArrayNode tokenBindingParameters = tokenBindingVersion.putArray("tokenBindingParameters");
            for (TokenBindingKeyParameters keyParameter : report.getSupportedTokenBindingKeyParameters()) {
                tokenBindingParameters.add(keyParameter.toString());
            }
            jsonReport.set("tokenBindingVersion", tokenBindingVersion);
        }
        appendTls13Groups(jsonReport);
        appendCurves(jsonReport);
//        appendSignatureAndHashAlgorithms(jsonReport);
        return jsonReport;
    }

    public void appendRandom(ObjectNode jsonReport) {
        prettyAppendRandom(jsonReport, "Random", report.getRandomEvaluationResult());
    }

    public void appendPublicKeyIssues(ObjectNode jsonReport) {
        ObjectNode publicKeyParameter = mapper.createObjectNode();
        publicKeyParameter.put("EC PublicKey reuse", String.valueOf(report.getResult(AnalyzedProperty.REUSES_EC_PUBLICKEY)));
        publicKeyParameter.put("DH PublicKey reuse", String.valueOf(report.getResult(AnalyzedProperty.REUSES_DH_PUBLICKEY)));
        publicKeyParameter.put("Uses Common DH Primes", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES)));
        if (report.getUsedCommonDhValueList() != null && report.getUsedCommonDhValueList().size() != 0) {
            ArrayNode CommonDhValues = publicKeyParameter.putArray("CommonDhValues");
            for (CommonDhValues value : report.getUsedCommonDhValueList()) {
                CommonDhValues.add(value.getName());
            }
        }
        publicKeyParameter.put("Uses only prime moduli", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI)));
        publicKeyParameter.put("Uses only safe-prime moduli", String.valueOf(report.getResult(AnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI)));
        if (report.getWeakestDhStrength() != null) {
            if (report.getWeakestDhStrength() < 1000) {
                publicKeyParameter.put("DH Strength", "" + report.getWeakestDhStrength());
            } else if (report.getWeakestDhStrength() < 2000) {
                publicKeyParameter.put("DH Strength", "" + report.getWeakestDhStrength());
            } else if (report.getWeakestDhStrength() < 4100) {
                publicKeyParameter.put("DH Strength", "" + report.getWeakestDhStrength());
            } else {
                publicKeyParameter.put("DH Strength", "" + report.getWeakestDhStrength());
            }
        }
        jsonReport.set("publicKeyParameter", publicKeyParameter);
    }

    public void appendScoringResults(ObjectNode jsonReport) {
        ObjectNode scoringResults = mapper.createObjectNode();

        SiteReportRater rater;
        try {
            rater = SiteReportRater.getSiteReportRater("en");
            ScoreReport scoreReport = rater.getScoreReport(report.getResultMap());
            scoringResults.put("Score", scoreReport.getScore());
            if (!detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                return;
            }
            ArrayNode scoreDetails = scoringResults.putArray("scoreDetails");
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
                scoreDetails.add(result);
            });
            jsonReport.set("scoringResults", scoringResults);
        } catch (JAXBException ex) {
            LOGGER.error("Exception Occured ", ex.getLocalizedMessage());
        }
    }

    public void appendRecommendations(ObjectNode jsonReport) {
        SiteReportRater rater;
        try {
            ArrayNode recommendationNode = jsonReport.putArray("recommendations");
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
                        recommendationNode.add(printFullRecommendation(rater, recommendation, influencer, resultRecommendation));
                    } else {
                        recommendationNode.add(printShortRecommendation(influencer, resultRecommendation));
                    }
                }
            });
        } catch (Exception ex) {
            LOGGER.error("Could not append recommendations", ex);
        }
    }

    private ObjectNode printFullRecommendation(SiteReportRater rater, Recommendation recommendation,
                                               PropertyResultRatingInfluencer influencer, PropertyResultRecommendation resultRecommendation) {
        ObjectNode recommendationNode = mapper.createObjectNode();
        recommendationNode.put("comments", recommendation.getShortName() + ": " + influencer.getResult());
        int scoreInluence = 0;
        String additionalInfo = "";
        if (influencer.getReferencedProperty() != null) {
            scoreInluence = rater
                    .getRatingInfluencers()
                    .getPropertyRatingInfluencer(influencer.getReferencedProperty(),
                            influencer.getReferencedPropertyResult()).getInfluence();
            Recommendation r = rater.getRecommendations().getRecommendation(influencer.getReferencedProperty());
            additionalInfo = " -> This score comes from \"" + r.getShortName() + "\"";
        } else {
            scoreInluence = influencer.getInfluence();
        }
        recommendationNode.put("Score", scoreInluence + additionalInfo);
        if (influencer.hasScoreCap()) {
            recommendationNode.put("Score cap", influencer.getScoreCap());
        }
        recommendationNode.put("Information", resultRecommendation.getShortDescription());
        recommendationNode.put("Recommendation", resultRecommendation.getHandlingRecommendation());
        return recommendationNode;
    }

    private String printShortRecommendation(PropertyResultRatingInfluencer influencer,
                                            PropertyResultRecommendation resultRecommendation) {
        return resultRecommendation.getShortDescription() + ". " + resultRecommendation.getHandlingRecommendation();

    }

    public ObjectNode appendCurves(ObjectNode jsonReport) {
        if (report.getSupportedNamedGroups() != null) {
            ArrayNode supportedNamedGroups = mapper.createArrayNode();
            if (report.getSupportedNamedGroups().size() > 0) {
                for (NamedGroup group : report.getSupportedNamedGroups()) {
                    ObjectNode namedGroup = mapper.createObjectNode();
                    namedGroup.put("Name", group.name());
                    if (detail == ScannerDetail.ALL) {
                        NamedCurveWitness witness = report.getSupportedNamedGroupsWitnesses().get(group);
                        for (CipherSuite cipher : witness.getCipherSuites()) {
                            namedGroup.put("Found using", cipher.toString());
                        }
                        if (witness.getEcdsaPkGroupEphemeral() != null && witness.getEcdsaPkGroupEphemeral() != group) {
                            namedGroup.put("ECDSA Required Groups", witness.getEcdsaPkGroupEphemeral() + " (Certificate Public Key - Ephemeral Cipher Suite)");
                        }
                        if (witness.getEcdsaSigGroupEphemeral() != null && witness.getEcdsaSigGroupEphemeral() != group) {
                            namedGroup.put("ECDSA Required Groups", witness.getEcdsaPkGroupEphemeral() + " (Certificate Signature  - Ephemeral Cipher Suite)");
                        }
                        if (witness.getEcdsaSigGroupStatic() != null && witness.getEcdsaSigGroupStatic() != group) {
                            namedGroup.put("ECDSA Required Groups", witness.getEcdsaPkGroupEphemeral() + " (Certificate Signature  - Static Cipher Suite)");
                        }
                    }
                    supportedNamedGroups.add(namedGroup);
                }
                if (report.getResult(AnalyzedProperty.GROUPS_DEPEND_ON_CIPHER) == TestResult.TRUE) {
                    supportedNamedGroups.add("Not all Groups are supported for all Cipher Suites");
                }
                if (report.getResult(AnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY) == TestResult.TRUE) {
                    supportedNamedGroups.add("Groups required for ECDSA validation are not enforced");
                }
            }
            jsonReport.set("supportedNamedGroups", supportedNamedGroups);
        }
        return jsonReport;
    }

    //    public ObjectNode appendSignatureAndHashAlgorithms(ObjectNode jsonReport) {
//        if (report.getSupportedSignatureAndHashAlgorithms() != null) {
//            prettyAppendHeading(builder, "Supported Signature and Hash Algorithms");
//            if (report.getSupportedSignatureAndHashAlgorithms().size() > 0) {
//                for (SignatureAndHashAlgorithm algorithm : report.getSupportedSignatureAndHashAlgorithms()) {
//                    prettyAppend(builder, algorithm.toString());
//                }
//            } else {
//                builder.append("none\n");
//            }
//        }
//        return jsonReport;
//    }
//
    public ObjectNode appendCompressions(ObjectNode jsonReport) {
        if (report.getSupportedCompressionMethods() != null) {
            ArrayNode supportedCompressions = jsonReport.putArray("Supported Compressions");
            for (CompressionMethod compression : report.getSupportedCompressionMethods()) {
                supportedCompressions.add(compression.name());
            }
        }
        return jsonReport;
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

    public ObjectNode appendTls13Groups(ObjectNode jsonReport) {
        if (report.getSupportedTls13Groups() != null) {
            if (report.getSupportedTls13Groups().size() > 0) {
                ArrayNode tls13NamedGroups = jsonReport.putArray("tls13NamedGroups");
                for (NamedGroup group : report.getSupportedTls13Groups()) {
                    tls13NamedGroups.add(group.name());
                }
            }
        }
        return jsonReport;
    }

    private void prettyAppendRandom(ObjectNode jsonReport, String testName,
                                    RandomEvaluationResult randomEvaluationResult) {
        ObjectNode nonce = mapper.createObjectNode();
        if (randomEvaluationResult == null) {
            nonce.put(testName, "unknown");
            return;
        }
        switch (randomEvaluationResult) {
            case DUPLICATES:
                nonce.put(testName, "true - exploitable");
                break;
            case NOT_ANALYZED:
                nonce.put(testName, "not analyzed");
                break;
            case NOT_RANDOM:
                nonce.put(testName, "does not seem to be random");
                break;
            case UNIX_TIME:
                nonce.put(testName, "contains unix time");
                break;
            case NO_DUPLICATES:
                nonce.put(testName, "no duplicates (wip)");
                break;
        }
        jsonReport.set("nonce", nonce);
    }

    public void appendPerformanceData(ObjectNode jsonReport) {
        ObjectNode performance = mapper.createObjectNode();
        if (detail.isGreaterEqualTo(ScannerDetail.ALL)) {
            try {
                performance.put("TCP connections", "" + report.getPerformedTcpConnections());
                for (PerformanceData data : report.getPerformanceList()) {
                    SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
                    Duration duration = new Duration(data.getStartTime(), data.getStopTime());
                    Period period = new Period(data.getStopTime() - data.getStartTime());
                    performance.put(data.getType().name(), PeriodFormat.getDefault().print(period));

                }
            } catch (Exception E) {
                LOGGER.debug("Exception Occured {}", E.getLocalizedMessage());
            }
            jsonReport.set("scannerPerformance", performance);
        } else {
            LOGGER.debug("Not printing performance data.");
        }
    }

    private void appendClientAuthentication(ObjectNode jsonReport) {

        ObjectNode clientAuthentication = mapper.createObjectNode();
        clientAuthentication.put("Supported", report.getCcaSupported());
        clientAuthentication.put("Required", report.getCcaRequired());

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
            ArrayNode ccaResultArray = clientAuthentication.putArray("ccaTestResult");
            for (CcaTestResult ccaTestResult : ccaTestResults) {
                ObjectNode ccaTestResultNode = mapper.createObjectNode();
                if (ccaTestResult.getWorkflowType() != lastCcaWorkflowType) {
                    lastCcaWorkflowType = ccaTestResult.getWorkflowType();
                    ccaTestResultNode.put(lastCcaWorkflowType.name(), ccaTestResult.getWorkflowType().name());
                }
                if (ccaTestResult.getCertificateType() != lastCcaCertificateType) {
                    lastCcaCertificateType = ccaTestResult.getCertificateType();
                    ccaTestResultNode.put(lastCcaCertificateType.name(), ccaTestResult.getCertificateType().name());
                }
                if (ccaTestResult.getProtocolVersion() != lastProtocolVersion) {
                    lastProtocolVersion = ccaTestResult.getProtocolVersion();
                    ccaTestResultNode.put(lastProtocolVersion.name(), ccaTestResult.getProtocolVersion().name());
                }

                ccaTestResultNode.put("cipherSuite", ccaTestResult.getCipherSuite().name());
                ccaTestResultNode.put("succeeded", ccaTestResult.getSucceeded());
                ccaResultArray.add(ccaTestResultNode);
            }
        }
        jsonReport.set("clientAuthentication", clientAuthentication);
    }

    private ObjectNode sessionTicketZeroKeyDetails(ObjectNode jsonReport) {
        ObjectNode sessionTicketZeroAttack = mapper.createObjectNode();
        if (report.getResult(AnalyzedProperty.VULNERABLE_TO_SESSION_TICKET_ZERO_KEY) == TestResult.TRUE) {
            sessionTicketZeroAttack.put("Has GnuTls magic bytes:", String.valueOf(report.getResult(AnalyzedProperty.HAS_GNU_TLS_MAGIC_BYTES)));
        }
        jsonReport.set("sessionTicketZeroAttack", sessionTicketZeroAttack);
        return jsonReport;
    }
}
