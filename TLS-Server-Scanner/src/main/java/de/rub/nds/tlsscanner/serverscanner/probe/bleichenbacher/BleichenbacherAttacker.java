/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher;

import de.rub.nds.protocol.constants.AsymmetricAlgorithmType;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.core.exceptions.AttackFailedException;
import de.rub.nds.tlsscanner.core.exceptions.OracleUnstableException;
import de.rub.nds.tlsscanner.core.task.FingerPrintTask;
import de.rub.nds.tlsscanner.core.task.FingerprintTaskVectorPair;
import de.rub.nds.tlsscanner.core.vector.VectorResponse;
import de.rub.nds.tlsscanner.core.vector.response.EqualityError;
import de.rub.nds.tlsscanner.core.vector.response.EqualityErrorTranslator;
import de.rub.nds.tlsscanner.core.vector.response.FingerprintChecker;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.constans.BleichenbacherScanType;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.constans.BleichenbacherWorkflowType;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.trace.BleichenbacherWorkflowGenerator;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.vector.Pkcs1Vector;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.vector.Pkcs1VectorGenerator;
import java.security.cert.CertificateParsingException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends differently formatted PKCS#1 messages to the TLS server and observes the server responses.
 * In case there are differences in the server responses, it is very likely that it is possible to
 * execute Bleichenbacher attacks.
 */
public class BleichenbacherAttacker {

    private static final Logger LOGGER = LogManager.getLogger();

    private ParallelExecutor executor;
    private Config tlsConfig;
    private BleichenbacherWorkflowType workflowType;
    private BleichenbacherScanType scanType;
    private int numberOfIterations;
    private ProtocolVersion testedVersion;
    private CipherSuite testedSuite;

    private boolean increasingTimeout = true;
    private long additionalTimeout = 1000;
    private long additionalTcpTimeout = 5000;
    private List<VectorResponse> fullResponseMap;

    public BleichenbacherAttacker(
            Config baseConfig,
            ParallelExecutor executor,
            BleichenbacherScanType scanType,
            BleichenbacherWorkflowType workflowType,
            int numberOfIterations,
            ProtocolVersion testedVersion,
            CipherSuite testedSuite) {
        this.tlsConfig = baseConfig;
        this.executor = executor;
        this.scanType = scanType;
        this.workflowType = workflowType;
        this.numberOfIterations = numberOfIterations;
        this.testedVersion = testedVersion;
        this.testedSuite = testedSuite;
    }

    public Boolean isVulnerable() {
        LOGGER.debug(
                "A server is considered vulnerable to this attack if it responds differently to the test vectors.");
        LOGGER.debug("A server is considered secure if it always responds the same way.");
        EqualityError referenceError = null;
        fullResponseMap = new LinkedList<>();
        try {
            for (int i = 0; i < numberOfIterations; i++) {
                List<VectorResponse> responseMap = createVectorResponseList();
                this.fullResponseMap.addAll(responseMap);
            }
        } catch (AttackFailedException e) {
            LOGGER.debug(e.getMessage());
            return null;
        }
        referenceError = getEqualityError(fullResponseMap);
        if (referenceError != EqualityError.NONE) {
            LOGGER.debug(
                    "Found a behavior difference within the responses. The server could be vulnerable.");
        } else {
            LOGGER.debug(
                    "Found no behavior difference within the responses. The server is very likely not vulnerable.");
        }

        LOGGER.debug(EqualityErrorTranslator.translation(referenceError, null, null));
        if (referenceError != EqualityError.NONE
                || LOGGER.getLevel().isMoreSpecificThan(Level.INFO)) {
            LOGGER.debug("-------------(Not Grouped)-----------------");
            for (VectorResponse vectorResponse : fullResponseMap) {
                LOGGER.debug(vectorResponse.toString());
            }
        }

        return referenceError != EqualityError.NONE;
    }

    private List<VectorResponse> createVectorResponseList() {
        prepareConfig();
        PublicKeyContainer publicKey = getServerPublicKey();
        if (publicKey.getAlgorithmType() != AsymmetricAlgorithmType.RSA) {
            throw new RuntimeException(
                    "Could not retrieve RSA public key from Server. Broken server config?");
        }
        RsaPublicKey rsaPublicKey = (RsaPublicKey) publicKey;
        if (publicKey == null) {
            LOGGER.fatal("Could not retrieve PublicKey from Server - is the Server running?");
            throw new OracleUnstableException("Fatal Extraction error");
        }
        List<TlsTask> taskList = new LinkedList<>();
        List<FingerprintTaskVectorPair> stateVectorPairList = new LinkedList<>();
        for (Pkcs1Vector vector :
                Pkcs1VectorGenerator.generatePkcs1Vectors(
                        rsaPublicKey,
                        scanType,
                        tlsConfig.getDefaultHighestClientProtocolVersion())) {
            State state =
                    new State(
                            tlsConfig,
                            BleichenbacherWorkflowGenerator.generateWorkflow(
                                    tlsConfig, workflowType, vector.getEncryptedValue()));
            FingerPrintTask fingerPrintTask =
                    new FingerPrintTask(
                            state,
                            additionalTimeout,
                            increasingTimeout,
                            executor.getReexecutions(),
                            additionalTcpTimeout);
            taskList.add(fingerPrintTask);
            stateVectorPairList.add(new FingerprintTaskVectorPair(fingerPrintTask, vector));
        }
        List<VectorResponse> tempResponseVectorList = new LinkedList<>();
        executor.bulkExecuteTasks(taskList);
        for (FingerprintTaskVectorPair pair : stateVectorPairList) {
            ResponseFingerprint fingerprint = null;
            if (pair.getFingerPrintTask().isHasError()) {
                LOGGER.warn("Could not extract fingerprint for " + pair.toString());
            } else {
                testedSuite =
                        pair.getFingerPrintTask()
                                .getState()
                                .getTlsContext()
                                .getSelectedCipherSuite();
                testedVersion =
                        pair.getFingerPrintTask()
                                .getState()
                                .getTlsContext()
                                .getSelectedProtocolVersion();
                if (testedSuite == null || testedVersion == null) {
                    LOGGER.fatal("Could not find ServerHello after successful extraction");
                    throw new OracleUnstableException("Fatal Extraction error");
                }
                fingerprint = pair.getFingerPrintTask().getFingerprint();
                tempResponseVectorList.add(new VectorResponse(pair.getVector(), fingerprint));
            }
        }
        // Check that the public key send by the server is actually the public key used to generate
        // the vectors. This is
        // currently a limitation of our script as the attack vectors are generated statically and
        // not dynamically. We
        // will adjust this in future versions.
        for (FingerprintTaskVectorPair pair : stateVectorPairList) {
            if (pair.getFingerPrintTask()
                                    .getState()
                                    .getTlsContext()
                                    .getPeerX509Context()
                                    .getSubjectRsaModulus()
                            != null
                    && !pair.getFingerPrintTask()
                            .getState()
                            .getTlsContext()
                            .getPeerX509Context()
                            .getSubjectRsaModulus()
                            .equals(rsaPublicKey.getModulus())) {
                throw new OracleUnstableException(
                        "Server sent us a different publickey during the scan. Aborting test");
            }
        }
        return tempResponseVectorList;
    }

    /**
     * This assumes that the responseVectorList only contains comparable vectors
     *
     * @param responseVectorList
     * @return
     */
    private EqualityError getEqualityError(List<VectorResponse> responseVectorList) {

        for (VectorResponse responseOne : responseVectorList) {
            for (VectorResponse responseTwo : responseVectorList) {
                if (responseOne == responseTwo) {
                    continue;
                }
                EqualityError error =
                        FingerprintChecker.checkEquality(
                                responseOne.getFingerprint(), responseTwo.getFingerprint());
                if (error != EqualityError.NONE) {
                    LOGGER.debug("Found an EqualityError: " + error);
                    LOGGER.debug("Fingerprint1: " + responseOne.getFingerprint().toString());
                    LOGGER.debug("Fingerprint2: " + responseTwo.getFingerprint().toString());
                    return error;
                }
            }
        }
        return EqualityError.NONE;
    }

    private PublicKeyContainer getServerPublicKey() {
        PublicKeyContainer publicKey = null;
        try {
            publicKey = CertificateFetcher.fetchServerPublicKey(tlsConfig);
        } catch (CertificateParsingException ignored) {
        }
        if (publicKey == null) {
            LOGGER.debug("Could not retrieve PublicKey from Server - is the Server running?");
            return null;
        }
        LOGGER.debug("Fetched the following server public key: " + publicKey);
        return publicKey;
    }

    private void prepareConfig() {
        tlsConfig.setHighestProtocolVersion(testedVersion);
        tlsConfig.setDefaultClientSupportedCipherSuites(testedSuite);
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(false);
        tlsConfig.setStopReceivingAfterFatal(false);
        tlsConfig.setStopActionsAfterFatal(false);
        tlsConfig.setStopActionsAfterWarning(false);
        tlsConfig.setWorkflowExecutorShouldClose(false);
    }

    public void setIncreasingTimeout(boolean increasingTimeout) {
        this.increasingTimeout = increasingTimeout;
    }

    public void setAdditionalTimeout(long additionalTimeout) {
        this.additionalTimeout = additionalTimeout;
    }

    public void setAdditionalTcpTimeout(long additionalTcpTimeout) {
        this.additionalTcpTimeout = additionalTcpTimeout;
    }

    public List<VectorResponse> getFullResponseMap() {
        return fullResponseMap;
    }
}
