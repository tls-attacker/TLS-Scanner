/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.CipherSuiteGrade;
import de.rub.nds.tlsscanner.core.report.CipherSuiteRater;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.ConnectionInsecure;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.HandshakeFailureReasons;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HandshakeSimulationAfterProbe extends AfterProbe<ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void analyze(ServerReport report) {
        int isSuccessfulCounter = 0;
        int isInsecureCounter = 0;

        List<SimulatedClientResult> simulatedclients = report.getSimulatedClientsResultList();
        if (simulatedclients != null) {
            for (SimulatedClientResult simulatedClient : simulatedclients) {
                if (simulatedClient.getReceivedAlert()) {
                    checkWhyAlert(report, simulatedClient);
                } else if (simulatedClient.getReceivedAllMandatoryMessages()) {
                    checkSelectedProtocolVersion(report, simulatedClient);
                    checkIfHandshakeWouldBeSuccessful(simulatedClient);
                    if (simulatedClient.getFailReasons().isEmpty()) {
                        simulatedClient.setHandshakeSuccessful(true);
                    }
                } else {
                    checkWhyMandatoryMessagesMissing(simulatedClient);
                }
                if (Objects.equals(simulatedClient.getHandshakeSuccessful(), Boolean.TRUE)) {
                    isSuccessfulCounter++;
                    checkIfConnectionIsInsecure(report, simulatedClient);
                    if (simulatedClient.getInsecureReasons().isEmpty()) {
                        simulatedClient.setConnectionInsecure(false);
                        checkIfConnectionIsRfc7918Secure(simulatedClient);
                    } else {
                        simulatedClient.setConnectionInsecure(true);
                        isInsecureCounter++;
                    }
                } else {
                    simulatedClient.setHandshakeSuccessful(false);
                }
            }
            report.putResult(TlsAnalyzedProperty.HANDSHAKE_SUCCESFUL_COUNTER, isSuccessfulCounter);
            report.putResult(
                    TlsAnalyzedProperty.HANDSHAKE_FAILED_COUNTER,
                    report.getSimulatedClientsResultList().size() - isSuccessfulCounter);
            report.putResult(TlsAnalyzedProperty.CONNECTION_INSECURE_COUNTER, isInsecureCounter);
        } else {
            LOGGER.debug(
                    "property "
                            + TlsAnalyzedProperty.CLIENT_SIMULATION_RESULTS.name()
                            + " requires a TestResult for the HandshakeSimulationAfterProbe but is null!");
        }
    }

    private void checkWhyAlert(ServerReport report, SimulatedClientResult simulatedClient) {
        if (isCipherSuiteMismatch(report, simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailureReasons.CIPHER_SUITE_MISMATCH);
        }
    }

    private boolean isCipherSuiteMismatch(
            ServerReport report, SimulatedClientResult simulatedClient) {
        Set<CipherSuite> ciphersuites = report.getSupportedCipherSuites();
        if (ciphersuites != null) {
            for (CipherSuite serverCipherSuite : ciphersuites) {
                for (CipherSuite clientCipherSuite :
                        simulatedClient.getClientSupportedCipherSuites()) {
                    if (serverCipherSuite.equals(clientCipherSuite)) {
                        return false;
                    }
                }
            }
        } else {
            LOGGER.debug(
                    "property "
                            + TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES.name()
                            + " requires a TestResult for the HandshakeSimulationAfterProbe but is null!");
        }
        return true;
    }

    private void checkSelectedProtocolVersion(
            ServerReport report, SimulatedClientResult simulatedClient) {
        List<ProtocolVersion> versions = report.getSupportedProtocolVersions();
        if (versions != null && simulatedClient.getSupportedVersionList() != null) {
            List<ProtocolVersion> commonProtocolVersions = new LinkedList<>();
            Collections.sort(versions);
            Collections.sort(simulatedClient.getSupportedVersionList());
            for (ProtocolVersion serverVersion : versions) {
                if (simulatedClient.getSupportedVersionList().contains(serverVersion)) {
                    commonProtocolVersions.add(serverVersion);
                }
            }
            Collections.sort(commonProtocolVersions);
            simulatedClient.setCommonProtocolVersions(commonProtocolVersions);
            if (!commonProtocolVersions.isEmpty()
                    && commonProtocolVersions
                            .get(commonProtocolVersions.size() - 1)
                            .equals(simulatedClient.getSelectedProtocolVersion())) {
                simulatedClient.setHighestPossibleProtocolVersionSelected(true);
            } else {
                simulatedClient.setHighestPossibleProtocolVersionSelected(false);
            }
        } else {
            LOGGER.debug(
                    "property "
                            + TlsAnalyzedProperty.VERSION_SUITE_PAIRS.name()
                            + " requires a TestResult for the HandshakeSimulationAfterProbe but is null!");
        }
    }

    private void checkIfHandshakeWouldBeSuccessful(SimulatedClientResult simulatedClient) {
        if (isProtocolMismatch(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailureReasons.PROTOCOL_MISMATCH);
        }
        if (isCipherSuiteForbidden(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailureReasons.CIPHER_SUITE_FORBIDDEN);
        }
        if (isPublicKeyLengthRsaNotAccepted(simulatedClient)) {
            simulatedClient.addToFailReasons(
                    HandshakeFailureReasons.RSA_CERTIFICATE_MODULUS_SIZE_NOT_ACCEPTED);
        }
        if (isPublicKeyLengthDhNotAccepted(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailureReasons.DHE_MODULUS_SIZE_NOT_ACCEPTED);
        }
    }

    private boolean isProtocolMismatch(SimulatedClientResult simulatedClient) {
        return simulatedClient.getCommonProtocolVersions() != null
                && simulatedClient.getCommonProtocolVersions().isEmpty();
    }

    private boolean isCipherSuiteForbidden(SimulatedClientResult simulatedClient) {
        if (simulatedClient
                .getSelectedCipherSuite()
                .isSupportedInProtocol(simulatedClient.getSelectedProtocolVersion())) {
            return false;
        } else if (simulatedClient.getVersionAcceptForbiddenCipherSuiteList() != null
                && simulatedClient
                        .getVersionAcceptForbiddenCipherSuiteList()
                        .contains(simulatedClient.getSelectedProtocolVersion())) {
            return false;
        }
        return true;
    }

    private boolean isPublicKeyLengthRsaNotAccepted(SimulatedClientResult simulatedClient) {
        List<Integer> supportedKeyLengths;
        Integer publicKeyLength = simulatedClient.getServerPublicKeyParameter();
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeRsa()
                && simulatedClient.getSupportedRsaKeySizeList() != null) {
            supportedKeyLengths = simulatedClient.getSupportedRsaKeySizeList();
            if (publicKeyLength < supportedKeyLengths.get(0)
                    || supportedKeyLengths.get(supportedKeyLengths.size() - 1) < publicKeyLength) {
                return true;
            }
        }
        return false;
    }

    private boolean isPublicKeyLengthDhNotAccepted(SimulatedClientResult simulatedClient) {
        List<Integer> supportedKeyLengths;
        Integer publicKeyLength = simulatedClient.getServerPublicKeyParameter();
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeDh()
                && simulatedClient.getSupportedDheKeySizeList() != null) {
            supportedKeyLengths = simulatedClient.getSupportedDheKeySizeList();
            if (publicKeyLength < supportedKeyLengths.get(0)
                    || supportedKeyLengths.get(supportedKeyLengths.size() - 1) < publicKeyLength) {
                return true;
            }
        }
        return false;
    }

    private void checkWhyMandatoryMessagesMissing(SimulatedClientResult simulatedClient) {
        if (isParsingError(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailureReasons.PARSING_ERROR);
        }
    }

    private boolean isParsingError(SimulatedClientResult simulatedClient) {
        return simulatedClient.getReceivedUnknown();
    }

    private void checkIfConnectionIsInsecure(
            ServerReport report, SimulatedClientResult simulatedClient) {
        if (simulatedClient.getSelectedCipherSuite() != null
                && isCipherSuiteGradeLow(simulatedClient)) {
            simulatedClient.addToInsecureReasons(
                    ConnectionInsecure.CIPHER_SUITE_GRADE_LOW.getReason());
        }
        checkVulnerabilities(report, simulatedClient);
        checkPublicKeySize(simulatedClient);
    }

    private boolean isCipherSuiteGradeLow(SimulatedClientResult simulatedClient) {
        return CipherSuiteRater.getGrade(simulatedClient.getSelectedCipherSuite())
                .equals(CipherSuiteGrade.LOW);
    }

    private void checkVulnerabilities(ServerReport report, SimulatedClientResult simulatedClient) {
        CipherSuite cipherSuite = simulatedClient.getSelectedCipherSuite();

        if (report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE) != null
                && report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE)
                        == TestResults.TRUE
                && cipherSuite.isCBC()) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PADDING_ORACLE.getReason());
        }
        if (report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER) != null
                && report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER)
                        == TestResults.TRUE
                && simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeRsa()) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.BLEICHENBACHER.getReason());
        }
        if (simulatedClient.getSelectedCompressionMethod() != CompressionMethod.NULL) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.CRIME.getReason());
        }
        if (report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32) != null
                && report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32)
                        == TestResults.TRUE) {
            if (cipherSuite.name().contains("3DES")
                    || cipherSuite.name().contains("IDEA")
                    || cipherSuite.name().contains("GOST")) {
                simulatedClient.addToInsecureReasons(ConnectionInsecure.SWEET32.getReason());
            }
        }
    }

    private void checkPublicKeySize(SimulatedClientResult simulatedClient) {
        Integer pubKey = simulatedClient.getServerPublicKeyParameter();
        Integer minRsa = 1024;
        Integer minDh = 1024;
        Integer minEcdh = 160;
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeRsa() && pubKey <= minRsa) {
            simulatedClient.addToInsecureReasons(
                    ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason()
                            + " - rsa > "
                            + minRsa);
        } else if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeDh() && pubKey <= minDh) {
            simulatedClient.addToInsecureReasons(
                    ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason() + " - dh > " + minDh);
        } else if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeEcdh()
                && pubKey <= minEcdh) {
            simulatedClient.addToInsecureReasons(
                    ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason()
                            + " - ecdh > "
                            + minEcdh);
        }
    }

    private void checkIfConnectionIsRfc7918Secure(SimulatedClientResult simulatedClient) {
        boolean isRfc7918Secure = false;
        CipherSuite cipherSuite = simulatedClient.getSelectedCipherSuite();
        Integer pubKey = simulatedClient.getServerPublicKeyParameter();
        if (cipherSuite != null && pubKey != null) {
            if (isProtocolVersionWhitelisted(simulatedClient)
                    && isSymmetricCipherRfc7918Whitelisted(cipherSuite)
                    && isKeyExchangeMethodWhitelisted(simulatedClient)
                    && isKeyLengthWhitelisted(simulatedClient, pubKey)) {
                isRfc7918Secure = true;
            }
        }
        simulatedClient.setConnectionRfc7918Secure(isRfc7918Secure);
    }

    private boolean isProtocolVersionWhitelisted(SimulatedClientResult simulatedClient) {
        return Objects.equals(
                        simulatedClient.getHighestPossibleProtocolVersionSelected(), Boolean.TRUE)
                && simulatedClient.getSelectedProtocolVersion() != ProtocolVersion.TLS10
                && simulatedClient.getSelectedProtocolVersion() != ProtocolVersion.TLS11;
    }

    private boolean isSymmetricCipherRfc7918Whitelisted(CipherSuite cipherSuite) {
        return cipherSuite.isGCM() || cipherSuite.isChachaPoly();
    }

    private boolean isKeyExchangeMethodWhitelisted(SimulatedClientResult simulatedClient) {
        switch (simulatedClient.getKeyExchangeAlgorithm()) {
            case DHE_DSS:
            case DHE_RSA:
            case ECDHE_ECDSA:
            case ECDHE_RSA:
                return true;
            default:
                return false;
        }
    }

    private boolean isKeyLengthWhitelisted(
            SimulatedClientResult simulatedClient, Integer keyLength) {
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeEcdh()
                && simulatedClient.getSelectedCipherSuite().isEphemeral()) {
            if (keyLength >= 3072) {
                return true;
            }
        }
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeEcdh()
                && simulatedClient.getSelectedCipherSuite().isEphemeral()) {
            if (keyLength >= 256) {
                return true;
            }
        }
        return false;
    }
}
