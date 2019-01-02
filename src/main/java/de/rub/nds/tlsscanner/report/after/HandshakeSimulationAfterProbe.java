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
                } else if (simulatedClient.getReceivedAllMandatoryMessages()) {
                    checkSelectedProtocolVersion(report, simulatedClient);
                    checkIfHandshakeWouldBeSuccessful(simulatedClient);
                } else {
                    checkWhyMandatoryMessagesMissing(simulatedClient);
                }
                if (simulatedClient.getFailReasons().isEmpty()) {
                    simulatedClient.setHandshakeSuccessful(true);
                    isSuccessfulCounter++;
                    checkIfConnectionIsInsecure(report, simulatedClient);
                    if (simulatedClient.getInsecureReasons().isEmpty()) {
                        simulatedClient.setConnectionInsecure(false);
                        checkIfConnectionIsRfc7918Secure(simulatedClient);
                        if (simulatedClient.getConnectionRfc7918Secure()) {
                            isRfc7918SecureCounter++;
                        }
                    } else {
                        simulatedClient.setConnectionInsecure(true);
                        isInsecureCounter++;
                    }
                } else {
                    simulatedClient.setHandshakeSuccessful(false);
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
            List<ProtocolVersion> commonProtocolVersions = new LinkedList<>();
            for (ProtocolVersion clientVersion : simulatedClient.getSupportedVersionList()) {
                if (report.getVersions().contains(clientVersion)) {
                    commonProtocolVersions.add(clientVersion);
                }
            }
            simulatedClient.setCommonProtocolVersions(commonProtocolVersions);
            if (!commonProtocolVersions.isEmpty()
                    && commonProtocolVersions.get(commonProtocolVersions.size() - 1).equals(simulatedClient.getSelectedProtocolVersion())) {
                simulatedClient.setHighestPossibleProtocolVersionSeleceted(true);
            } else {
                simulatedClient.setHighestPossibleProtocolVersionSeleceted(false);
            }
        }
    }

    private void checkIfHandshakeWouldBeSuccessful(SimulatedClient simulatedClient) {
        if (isProtocolMismatch(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PROTOCOL_MISMATCH.getReason());
        }
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

    private boolean isProtocolMismatch(SimulatedClient simulatedClient) {
        return simulatedClient.getCommonProtocolVersions() != null && simulatedClient.getCommonProtocolVersions().isEmpty();
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

    private void checkWhyMandatoryMessagesMissing(SimulatedClient simulatedClient) {
        boolean reasonFound = false;
        if (isParsingError(simulatedClient)) {
            simulatedClient.addToFailReasons(HandshakeFailed.PARSING_ERROR.getReason());
            reasonFound = true;
        }
        if (!reasonFound) {
            simulatedClient.addToFailReasons(HandshakeFailed.UNKNOWN.getReason());
        }
    }

    private boolean isParsingError(SimulatedClient simulatedClient) {
        return simulatedClient.getReceivedUnknown();
    }

    private void checkIfConnectionIsInsecure(SiteReport report, SimulatedClient simulatedClient) {
        if (isCipherSuiteGradeLow(simulatedClient)) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.CIPHERSUITE_GRADE_LOW.getReason());
        }
        checkVulnerabilities(report, simulatedClient);
        checkPublicKeySize(simulatedClient);
    }

    private boolean isCipherSuiteGradeLow(SimulatedClient simulatedClient) {
        return CiphersuiteRater.getGrade(simulatedClient.getSelectedCiphersuite()).equals(CipherSuiteGrade.LOW);
    }

    private void checkVulnerabilities(SiteReport report, SimulatedClient simulatedClient) {
        CipherSuite cipherSuite = simulatedClient.getSelectedCiphersuite();
        if (report.getPaddingOracleVulnerable() != null && report.getPaddingOracleVulnerable()
                && cipherSuite.isCBC()) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PADDING_ORACLE.getReason());
        }
        if (report.getBleichenbacherVulnerable() != null && report.getBleichenbacherVulnerable()
                && simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeRsa()) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.BLEICHENBACHER.getReason());
        }
        if (simulatedClient.getSelectedCompressionMethod() != CompressionMethod.NULL) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.CRIME.getReason());
        }
        if (report.getSweet32Vulnerable() != null && report.getSweet32Vulnerable()) {
            if (cipherSuite.name().contains("3DES")
                    || cipherSuite.name().contains("IDEA")
                    || cipherSuite.name().contains("GOST")) {
                simulatedClient.addToInsecureReasons(ConnectionInsecure.SWEET32.getReason());
            }
        }
    }

    private void checkPublicKeySize(SimulatedClient simulatedClient) {
        Integer pubKey = simulatedClient.getServerPublicKeyParameter();
        Integer minRsa = 1024;
        Integer minDh = 1024;
        Integer minEcdh = 160;
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeRsa() && pubKey <= minRsa) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason() + " - rsa > " + minRsa);
        } else if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeDh() && pubKey <= minDh) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason() + " - dh > " + minDh);
        } else if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeEcdh() && pubKey <= minEcdh) {
            simulatedClient.addToInsecureReasons(ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason() + " - ecdh > " + minEcdh);
        }
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
