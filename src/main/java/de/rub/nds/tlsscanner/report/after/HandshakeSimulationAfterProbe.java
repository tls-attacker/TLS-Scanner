/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.constants.CipherSuiteGrade;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.HandshakeFailed;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.ConnectionInsecure;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
import de.rub.nds.tlsscanner.report.CiphersuiteRater;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

public class HandshakeSimulationAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        int isSuccessfulCounter = 0;
        int isInsecureCounter = 0;
        int isRfc7918SecureCounter = 0;
        if (report.getSimulatedClientList() != null) {
            for (SimulatedClient simulatedClient : report.getSimulatedClientList()) {
                if (simulatedClient.getReceivedServerHello()) {
                    checkHighestPossibleProtocolVersionSeleceted(report, simulatedClient);
                    if (simulatedClient.getReceivedServerHelloDone()) {
                        checkIfHandshakeWouldBeSuccessful(simulatedClient);
                    } else {
                        simulatedClient.setHandshakeSuccessful(false);
                        checkWhyServerHelloDoneIsMissing(report, simulatedClient);
                    }
                } else {
                    simulatedClient.setHandshakeSuccessful(false);
                    checkWhyServerHelloIsMissing(report, simulatedClient);
                }
                if (simulatedClient.getHandshakeSuccessful()) {
                    isSuccessfulCounter++;
                    checkIfConnectionIsInsecure(report, simulatedClient);
                    if (simulatedClient.getConnectionInsecure()) {
                        isInsecureCounter++;
                    } else {
                        checkIfConnectionIsRfc7918Secure(simulatedClient);
                        if (simulatedClient.getConnectionRfc7918Secure()) {
                            isRfc7918SecureCounter++;
                        }
                    }
                }
            }
            report.setHandshakeSuccessfulCounter(isSuccessfulCounter);
            report.setHandshakeFailedCounter(report.getSimulatedClientList().size() - isSuccessfulCounter);
            report.setConnectionInsecureCounter(isInsecureCounter);
            report.setConnectionRfc7918SecureCounter(isRfc7918SecureCounter);
        }
    }

    private void checkHighestPossibleProtocolVersionSeleceted(SiteReport report, SimulatedClient simulatedClient) {
        if (report.getVersions() != null) {
            if (simulatedClient.getSelectedProtocolVersion().equals(simulatedClient.getHighestClientProtocolVersion())) {
                simulatedClient.setHighestPossibleProtocolVersionSeleceted(true);
            } else {
                boolean serverSupportsClientVersion = false;
                for (ProtocolVersion version : report.getVersions()) {
                    if (version.equals(simulatedClient.getHighestClientProtocolVersion())) {
                        serverSupportsClientVersion = true;
                    }
                }
                if (!serverSupportsClientVersion) {
                    simulatedClient.setHighestPossibleProtocolVersionSeleceted(true);
                } else {
                    simulatedClient.setHighestPossibleProtocolVersionSeleceted(false);
                }
            }
        }
    }

    private void checkIfHandshakeWouldBeSuccessful(SimulatedClient simulatedClient) {
        boolean reallySuccessful = true;
        if (isCiphersuiteForbidden(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.CIPHERSUITE_FORBIDDEN.getReason());
            reallySuccessful = false;
        }
        if (isPublicKeyLengthRsaNotAccepted(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PUBLIC_KEY_SIZE_RSA_NOT_ACCEPTED.getReason() + " - supported sizes: "
                    + simulatedClient.getSupportedRsaKeySizeList());
            reallySuccessful = false;
        }
        if (isPublicKeyLengthDhNotAccepted(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PUBLIC_KEY_SIZE_DH_NOT_ACCEPTED.getReason() + " - supported sizes: "
                    + simulatedClient.getSupportedDheKeySizeList());
            reallySuccessful = false;
        }
        simulatedClient.setHandshakeSuccessful(reallySuccessful);
    }

    private boolean isCiphersuiteForbidden(SimulatedClient simulatedClient) {
        if (simulatedClient.getSelectedCiphersuite().isSupportedInProtocol(simulatedClient.getSelectedProtocolVersion())) {
            return false;
        } else if (simulatedClient.getVersionAcceptForbiddenCiphersuiteList() != null
                && simulatedClient.getVersionAcceptForbiddenCiphersuiteList().contains(simulatedClient.getSelectedProtocolVersion())) {
            return false;
        }
        return true;
    }

    private boolean isPublicKeyLengthRsaNotAccepted(SimulatedClient simulatedClient) {
        List<Integer> supportedKeyLengths;
        Integer publicKeyLength = simulatedClient.getServerPublicKeyParameter();
        KeyExchangeAlgorithm kea = AlgorithmResolver.getKeyExchangeAlgorithm(simulatedClient.getSelectedCiphersuite());
        if (kea != null && kea.isKeyExchangeRsa() && simulatedClient.getSupportedRsaKeySizeList() != null) {
            supportedKeyLengths = simulatedClient.getSupportedRsaKeySizeList();
            if (publicKeyLength < supportedKeyLengths.get(0)
                    || supportedKeyLengths.get(supportedKeyLengths.size() - 1) < publicKeyLength) {
                return true;
            }
        }
        return false;
    }

    private boolean isPublicKeyLengthDhNotAccepted(SimulatedClient simulatedClient) {
        List<Integer> supportedKeyLengths;
        Integer publicKeyLength = simulatedClient.getServerPublicKeyParameter();
        KeyExchangeAlgorithm kea = AlgorithmResolver.getKeyExchangeAlgorithm(simulatedClient.getSelectedCiphersuite());
        if (kea != null && kea.isKeyExchangeDh() && simulatedClient.getSupportedDheKeySizeList() != null) {
            supportedKeyLengths = simulatedClient.getSupportedDheKeySizeList();
            if (publicKeyLength < supportedKeyLengths.get(0)
                    || supportedKeyLengths.get(supportedKeyLengths.size() - 1) < publicKeyLength) {
                return true;
            }
        }
        return false;
    }

    private void checkWhyServerHelloIsMissing(SiteReport report, SimulatedClient simulatedClient) {
        boolean reasonFound = false;
        if (isProtocolMismatch(report, simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PROTOCOL_MISMATCH.getReason());
            reasonFound = true;
        } else if (isCiphersuiteMismatch(report, simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.CIPHERSUITE_MISMATCH.getReason());
            reasonFound = true;
        } else if (isParsingError(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PARSING_ERROR.getReason());
            reasonFound = true;
        }
        if (!reasonFound) {
            simulatedClient.addToFailReasons(HandshakeFailed.UNKNOWN.getReason());
        }
    }

    private void checkWhyServerHelloDoneIsMissing(SiteReport report, SimulatedClient simulatedClient) {
        boolean reasonFound = false;
        if (isProtocolMismatch(report, simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PROTOCOL_MISMATCH.getReason());
            reasonFound = true;
        } else if (isCiphersuiteMismatch(report, simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.CIPHERSUITE_MISMATCH.getReason());
            reasonFound = true;
        }
        if (!reasonFound) {
            simulatedClient.addToFailReasons(HandshakeFailed.UNKNOWN.getReason());
        }
    }

    private boolean isProtocolMismatch(SiteReport report, SimulatedClient simulatedClient) {
        if (report.getVersions() != null) {
            for (ProtocolVersion serverVersion : report.getVersions()) {
                for (ProtocolVersion clientVersion : simulatedClient.getSupportedVersionList()) {
                    if (serverVersion.equals(clientVersion)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private boolean isCiphersuiteMismatch(SiteReport report, SimulatedClient simulatedClient) {
        if (report.getCipherSuites() != null) {
            for (CipherSuite serverCipherSuite : report.getCipherSuites()) {
                for (CipherSuite clientCipherSuite : simulatedClient.getClientSupportedCiphersuites()) {
                    if (serverCipherSuite.equals(clientCipherSuite)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private boolean isParsingError(SimulatedClient simulatedClient) {
        int counter = 0;
        if (simulatedClient.getReceivedCertificate()) {
            counter++;
        }
        if (simulatedClient.getReceivedServerKeyExchange()) {
            counter++;
        }
        if (simulatedClient.getReceivedServerHelloDone()) {
            counter++;
        }
        if (counter == 0 && !simulatedClient.getReceivedUnknown()) {
            return false;
        }
        return true;
    }

    private void checkIfConnectionIsInsecure(SiteReport report, SimulatedClient simulatedClient) {
        boolean connectionInsecure = false;
        if (isCipherSuiteGradeLow(simulatedClient)) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.CIPHERSUITE_GRADE_LOW.getReason());
            connectionInsecure = true;
        }
        if (isVulnerable(report, simulatedClient)) {
            connectionInsecure = true;
        }
        if (isPublicKeyLengthToSmall(simulatedClient)) {
            connectionInsecure = true;
        }
        simulatedClient.setConnectionInsecure(connectionInsecure);
    }

    private boolean isCipherSuiteGradeLow(SimulatedClient simulatedClient) {
        return CiphersuiteRater.getGrade(simulatedClient.getSelectedCiphersuite()).equals(CipherSuiteGrade.LOW);
    }

    private boolean isVulnerable(SiteReport report, SimulatedClient simulatedClient) {
        CipherSuite cipherSuite = simulatedClient.getSelectedCiphersuite();
        boolean isVulnerable = false;
        if (report.getPaddingOracleVulnerable() != null && report.getPaddingOracleVulnerable()
                && cipherSuite.isCBC()) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PADDING_ORACLE.getReason());
            isVulnerable = true;
        }
        if (report.getBleichenbacherVulnerable() != null && report.getBleichenbacherVulnerable()
                && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).isKeyExchangeRsa()) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.BLEICHENBACHER.getReason());
            isVulnerable = true;
        }
        if (simulatedClient.getSelectedCompressionMethod() != CompressionMethod.NULL) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.CRIME.getReason());
            isVulnerable = true;
        }
        if (report.getSweet32Vulnerable() != null && report.getSweet32Vulnerable()) {
            if (cipherSuite.name().contains("3DES")
                    || cipherSuite.name().contains("IDEA")
                    || cipherSuite.name().contains("GOST")) {
                simulatedClient.addToInsecureReasons(ConnectionInsecure.SWEET32.getReason());
                isVulnerable = true;
            }
        }
        return isVulnerable;
    }

    private boolean isPublicKeyLengthToSmall(SimulatedClient simulatedClient) {
        KeyExchangeAlgorithm kea = AlgorithmResolver.getKeyExchangeAlgorithm(simulatedClient.getSelectedCiphersuite());
        Integer pubKey = simulatedClient.getServerPublicKeyParameter();
        Integer minRsa = 1024;
        Integer minDh = 1024;
        Integer minEcdh = 160;
        if (kea != null && kea.isKeyExchangeRsa() && pubKey <= minRsa) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason() + " - rsa > " + minRsa);
            return true;
        } else if (kea != null && kea.isKeyExchangeDh() && pubKey <= minDh) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason() + " - dh > " + minDh);
            return true;
        } else if (kea != null && kea.isKeyExchangeEcdh() && pubKey <= minEcdh) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason() + " - ecdh > " + minEcdh);
            return true;
        }
        return false;
    }

    private void checkIfConnectionIsRfc7918Secure(SimulatedClient simulatedClient) {
        boolean isRfc7918Secure = false;
        CipherSuite cipherSuite = simulatedClient.getSelectedCiphersuite();
        Integer pubKey = simulatedClient.getServerPublicKeyParameter();
        if (cipherSuite != null && pubKey != null) {
            if (isProtocolVersionWhitelisted(simulatedClient)
                    && isSymmetricCipherRfc7918Whitelisted(cipherSuite)
                    && isKeyExchangeMethodWhitelisted(cipherSuite)
                    && isKeyLengthWhitelisted(cipherSuite, pubKey)) {
                isRfc7918Secure = true;
            }
        }
        simulatedClient.setConnectionRfc7918Secure(isRfc7918Secure);
    }

    private boolean isProtocolVersionWhitelisted(SimulatedClient simulatedClient) {
        return simulatedClient.getHighestPossibleProtocolVersionSeleceted()
                && simulatedClient.getSelectedProtocolVersion() != ProtocolVersion.TLS10
                && simulatedClient.getSelectedProtocolVersion() != ProtocolVersion.TLS11;
    }

    private boolean isSymmetricCipherRfc7918Whitelisted(CipherSuite cipherSuite) {
        return cipherSuite.isGCM() || cipherSuite.isChachaPoly();
    }

    private boolean isKeyExchangeMethodWhitelisted(CipherSuite cipherSuite) {
        switch (AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)) {
            case DHE_DSS:
            case DHE_RSA:
            case ECDHE_ECDSA:
            case ECDHE_RSA:
                return true;
            default:
                return false;
        }
    }

    private boolean isKeyLengthWhitelisted(CipherSuite cipherSuite, Integer keyLength) {
        KeyExchangeAlgorithm kea = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);
        if (kea != null && kea.isKeyExchangeEcdh() && cipherSuite.isEphemeral()) {
            if (keyLength >= 3072) {
                return true;
            }
        }
        if (kea != null && kea.isKeyExchangeEcdh() && cipherSuite.isEphemeral()) {
            if (keyLength >= 256) {
                return true;
            }
        }
        return false;
    }
}
