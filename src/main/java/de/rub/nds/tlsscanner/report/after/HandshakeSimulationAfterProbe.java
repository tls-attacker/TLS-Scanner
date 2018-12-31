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
import java.util.LinkedList;
import java.util.List;

public class HandshakeSimulationAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        int isSuccessfulCounter = 0;
        int isInsecureCounter = 0;
        int isRfc7918SecureCounter = 0;
        if (report.getSimulatedClientList() != null) {
            for (SimulatedClient simulatedClient : report.getSimulatedClientList()) {
                if (simulatedClient.getReceivedAlert()) {
                    checkWhyAlert(report, simulatedClient);
                } else if (simulatedClient.getFailReasons().isEmpty()) {
                    checkSelectedProtocolVersion(report, simulatedClient);
                    checkIfHandshakeWouldBeSuccessful(simulatedClient);
                }
                if (simulatedClient.getFailReasons().isEmpty()) {
                    simulatedClient.setHandshakeSuccessful(true);
                } else {
                    simulatedClient.setHandshakeSuccessful(false);
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

    private void checkWhyAlert(SiteReport report, SimulatedClient simulatedClient) {
        boolean reasonFound = false;
        if (isCiphersuiteMismatch(report, simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.CIPHERSUITE_MISMATCH.getReason());
            reasonFound = true;
        }
        if (!reasonFound) {
            simulatedClient.addToFailReasons(HandshakeFailed.UNKNOWN.getReason());
        }
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

    private void checkSelectedProtocolVersion(SiteReport report, SimulatedClient simulatedClient) {
        if (report.getVersions() != null) {
            List<ProtocolVersion> testList = new LinkedList<>();
            for (ProtocolVersion clientVersion : simulatedClient.getSupportedVersionList()) {
                if (report.getVersions().contains(clientVersion)) {
                    testList.add(clientVersion);
                }
            }
            if (testList.isEmpty()) {
                simulatedClient.addToFailReasons(HandshakeFailed.PROTOCOL_MISMATCH.getReason());
            } else if (testList.get(testList.size() - 1).equals(simulatedClient.getSelectedProtocolVersion())) {
                simulatedClient.setHighestPossibleProtocolVersionSeleceted(true);
            } else {
                simulatedClient.setHighestPossibleProtocolVersionSeleceted(false);
            }
        }
    }

    private void checkIfHandshakeWouldBeSuccessful(SimulatedClient simulatedClient) {
        if (isCiphersuiteForbidden(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.CIPHERSUITE_FORBIDDEN.getReason());
        }
        if (isPublicKeyLengthRsaNotAccepted(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PUBLIC_KEY_SIZE_RSA_NOT_ACCEPTED.getReason() + " - supported sizes: "
                    + simulatedClient.getSupportedRsaKeySizeList());
        }
        if (isPublicKeyLengthDhNotAccepted(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PUBLIC_KEY_SIZE_DH_NOT_ACCEPTED.getReason() + " - supported sizes: "
                    + simulatedClient.getSupportedDheKeySizeList());
        }
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
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeRsa() && simulatedClient.getSupportedRsaKeySizeList() != null) {
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
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeDh() && simulatedClient.getSupportedDheKeySizeList() != null) {
            supportedKeyLengths = simulatedClient.getSupportedDheKeySizeList();
            if (publicKeyLength < supportedKeyLengths.get(0)
                    || supportedKeyLengths.get(supportedKeyLengths.size() - 1) < publicKeyLength) {
                return true;
            }
        }
        return false;
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
                && simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeRsa()) {
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
        Integer pubKey = simulatedClient.getServerPublicKeyParameter();
        Integer minRsa = 1024;
        Integer minDh = 1024;
        Integer minEcdh = 160;
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeRsa() && pubKey <= minRsa) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason() + " - rsa > " + minRsa);
            return true;
        } else if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeDh() && pubKey <= minDh) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason() + " - dh > " + minDh);
            return true;
        } else if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeEcdh() && pubKey <= minEcdh) {
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
                    && isKeyExchangeMethodWhitelisted(simulatedClient)
                    && isKeyLengthWhitelisted(simulatedClient, pubKey)) {
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

    private boolean isKeyExchangeMethodWhitelisted(SimulatedClient simulatedClient) {
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

    private boolean isKeyLengthWhitelisted(SimulatedClient simulatedClient, Integer keyLength) {
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeEcdh() && simulatedClient.getSelectedCiphersuite().isEphemeral()) {
            if (keyLength >= 3072) {
                return true;
            }
        }
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeEcdh() && simulatedClient.getSelectedCiphersuite().isEphemeral()) {
            if (keyLength >= 256) {
                return true;
            }
        }
        return false;
    }
}
