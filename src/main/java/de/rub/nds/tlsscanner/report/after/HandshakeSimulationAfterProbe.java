/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.constants.CipherSuiteGrade;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.HandshakeFailed;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.ConnectionInsecure;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
import de.rub.nds.tlsscanner.report.CiphersuiteRater;
import de.rub.nds.tlsscanner.report.SiteReport;

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
                }
                if (simulatedClient.getReceivedServerHelloDone()) {
                    checkIfHandshakeWouldBeSuccessful(simulatedClient);
                } else {
                    simulatedClient.setHandshakeSuccessful(false);
                    checkWhyServerHelloDoneIsMissing(report, simulatedClient);
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
            simulatedClient.addToFailReasons(HandshakeFailed.CIPHERSUITE_FORBIDDEN);
            reallySuccessful = false;
        }
        if (isPublicKeyLengthNotAccepted(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PUBLIC_KEY_LENGTH_NOT_ACCEPTED);
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

    private boolean isPublicKeyLengthNotAccepted(SimulatedClient simulatedClient) {
        if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_RSA")
                && simulatedClient.getSupportedRsaKeyLengthList() != null
                && !simulatedClient.getSupportedRsaKeyLengthList().contains(Integer.parseInt(simulatedClient.getServerPublicKeyLength()))) {
            return true;
        } else if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_DH")
                && simulatedClient.getSupportedDheKeyLengthList() != null
                && !simulatedClient.getSupportedDheKeyLengthList().contains(Integer.parseInt(simulatedClient.getServerPublicKeyLength()))) {
            return true;
        }
        return false;
    }

    private void checkWhyServerHelloDoneIsMissing(SiteReport report, SimulatedClient simulatedClient) {
        boolean reasonFound = false;
        if (isProtocolMismatch(report, simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PROTOCOL_MISMATCH);
            reasonFound = true;
        } else if (isCiphersuiteMismatch(report, simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.CIPHERSUITE_MISMATCH);
            reasonFound = true;
        }
        if (!reasonFound) {
            simulatedClient.addToFailReasons(HandshakeFailed.UNKNOWN);
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

    private void checkIfConnectionIsInsecure(SiteReport report, SimulatedClient simulatedClient) {
        boolean connectionInsecure = false;
        if (isCipherSuiteGradeLow(simulatedClient)) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.CIPHERSUITE_GRADE_LOW);
            connectionInsecure = true;
        }
        if (isVulnerable(report, simulatedClient)) {
            connectionInsecure = true;
        }
        simulatedClient.setConnectionInsecure(connectionInsecure);
    }

    private boolean isCipherSuiteGradeLow(SimulatedClient simulatedClient) {
        return CiphersuiteRater.getGrade(simulatedClient.getSelectedCiphersuite()).equals(CipherSuiteGrade.LOW);
    }

    private boolean isVulnerable(SiteReport report, SimulatedClient simulatedClient) {
        boolean isVulnerable = false;
        if (report.getPaddingOracleVulnerable() != null && report.getPaddingOracleVulnerable()
                && simulatedClient.getSelectedCiphersuite().isCBC()) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PADDING_ORACLE);
            isVulnerable = true;
        }
        if (report.getBleichenbacherVulnerable() != null && report.getBleichenbacherVulnerable()
                && simulatedClient.getSelectedCiphersuite().name().contains("TLS_RSA")) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.BLEICHENBACHER);
            isVulnerable = true;
        }
        if (simulatedClient.getSelectedCompressionMethod() != CompressionMethod.NULL) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.CRIME);
            isVulnerable = true;
        }
        if (report.getSweet32Vulnerable() != null && report.getSweet32Vulnerable()) {
            if (simulatedClient.getSelectedCiphersuite().name().contains("3DES")
                    || simulatedClient.getSelectedCiphersuite().name().contains("IDEA")
                    || simulatedClient.getSelectedCiphersuite().name().contains("GOST")) {
                simulatedClient.addToInsecureReasons(ConnectionInsecure.SWEET32);
                isVulnerable = true;
            }
        }
        return isVulnerable;
    }

    private void checkIfConnectionIsRfc7918Secure(SimulatedClient simulatedClient) {
        boolean isRfc7918Secure = false;
        CipherSuite cipherSuite = simulatedClient.getSelectedCiphersuite();
        String keyLengthString = simulatedClient.getServerPublicKeyLength();
        if (cipherSuite != null && keyLengthString != null) {
            Integer keyLength = Integer.parseInt(keyLengthString);
            if (isProtocolVersionWhitelisted(simulatedClient)
                    && isSymmetricCipherRfc7918Whitelisted(cipherSuite)
                    && isKeyExchangeMethodWhitelisted(cipherSuite)
                    && isKeyLengthWhitelisted(cipherSuite, keyLength)) {
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
        return cipherSuite.name().contains("AES_128_GCM_SHA256") || cipherSuite.name().contains("AES_256_GCM_SHA384");
    }

    private boolean isKeyExchangeMethodWhitelisted(CipherSuite cipherSuite) {
        if (cipherSuite.name().contains("DHE_RSA")
                || cipherSuite.name().contains("DHE_DSS")) {
            return true;
        }
        if (cipherSuite.name().contains("ECDHE_RSA")
                || cipherSuite.name().contains("ECDHE_ECDSA")) {
            return true;
        }
        return false;
    }

    private boolean isKeyLengthWhitelisted(CipherSuite cipherSuite, Integer keyLength) {
        if (cipherSuite.name().contains("TLS_DHE")) {
            if (keyLength >= 3072) {
                return true;
            }
        }
        if (cipherSuite.name().contains("TLS_ECDHE")) {
            if (keyLength >= 256) {
                return true;
            }
        }
        return false;
    }
}
