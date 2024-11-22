/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.drown;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.constans.DrownOracleType;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.constans.DrownVulnerabilityType;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SpecialDrownAttacker extends BaseDrownAttacker {

    private static final Logger LOGGER = LogManager.getLogger();

    private DrownOracleType oracleType;
    private String checkDataFilePath;
    private boolean generateCheckData;
    private boolean analyzeCheckData;

    public SpecialDrownAttacker(
            Config baseConfig, ParallelExecutor executor, DrownOracleType oracleType) {
        super(baseConfig, executor);
        this.oracleType = oracleType;
    }

    public SpecialDrownAttacker(
            Config baseConfig,
            ParallelExecutor executor,
            DrownOracleType oracleType,
            String checkDataFilePath,
            boolean generateCheckData,
            boolean analyzeCheckData) {
        super(baseConfig, executor);
        this.oracleType = oracleType;
        this.checkDataFilePath = checkDataFilePath;
        this.generateCheckData = generateCheckData;
        this.analyzeCheckData = analyzeCheckData;
    }

    @Override
    public DrownVulnerabilityType getDrownVulnerabilityType() {
        DrownVulnerabilityType vulnerabilityType = DrownVulnerabilityType.UNKNOWN;
        if (oracleType == DrownOracleType.EXTRA_CLEAR) {
            return checkForExtraClearOracle(tlsConfig);
        }
        if (oracleType == DrownOracleType.LEAKY_EXPORT) {
            if (checkDataFilePath == null) {
                throw new ConfigurationException("Check data file is required");
            }
            if (!generateCheckData && !analyzeCheckData) {
                throw new ConfigurationException(
                        "Specify whether to generate or analyze check data");
            }
            if (generateCheckData) {
                vulnerabilityType = generateLeakyExportCheckData(tlsConfig, checkDataFilePath);
            }
            if (analyzeCheckData) {
                vulnerabilityType = checkForLeakyExport(tlsConfig, checkDataFilePath);
            }
        }
        return vulnerabilityType;
    }

    private DrownVulnerabilityType checkForExtraClearOracle(Config config) {
        SSL2CipherSuite cipherSuite = config.getDefaultSSL2CipherSuite();

        // Overwrite all but 1 byte of the full key with null bytes
        int clearKeyLength =
                cipherSuite.getClearKeyByteNumber() + cipherSuite.getSecretKeyByteNumber() - 1;
        byte[] clearKey = new byte[clearKeyLength];
        SSL2ClientMasterKeyMessage clientMasterKeyMessage = new SSL2ClientMasterKeyMessage();
        clientMasterKeyMessage.setClearKeyData(Modifiable.explicit(clearKey));

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.SSL2_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(clientMasterKeyMessage));
        trace.addTlsAction(new ReceiveAction(new SSL2ServerVerifyMessage()));
        State state = new State(config, trace);
        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();

        if (!WorkflowTraceResultUtil.didReceiveMessage(trace, SSL2MessageType.SSL_SERVER_HELLO)) {
            return DrownVulnerabilityType.NONE;
        }

        SSL2ServerVerifyMessage serverVerifyMessage =
                (SSL2ServerVerifyMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                trace, SSL2MessageType.SSL_SERVER_VERIFY);
        if (serverVerifyMessage != null
                && ServerVerifyChecker.check(serverVerifyMessage, state.getTlsContext(), true)) {
            return DrownVulnerabilityType.SPECIAL;
        }

        return DrownVulnerabilityType.SSL2;
    }

    /**
     * Connects to a target host and writes a file to disk which will allow checkForLeakyExport() to
     * check whether the server is affected by the "leaky export" oracle bug (CVE-2016-0704).
     *
     * @param dataFilePath Name of the data dump file for checkForLeakyExport().
     * @return Information whether the server is vulnerable, if already known
     */
    private DrownVulnerabilityType generateLeakyExportCheckData(
            Config config, String dataFilePath) {
        SSL2CipherSuite cipherSuite = config.getDefaultSSL2CipherSuite();

        // Produce correctly-padded SECRET-KEY-DATA of the wrong length (case 2
        // from the DROWN paper)
        int secretKeyLength = cipherSuite.getSecretKeyByteNumber() + 2;
        byte[] secretKey = new byte[secretKeyLength];
        for (int i = 0; i < secretKeyLength; i++) {
            secretKey[i] = (byte) 0xFF;
        }
        SSL2ClientMasterKeyMessage clientMasterKeyMessage = new SSL2ClientMasterKeyMessage();
        // Make sure computations are already in place for the next step
        clientMasterKeyMessage.prepareComputations();
        // The Premaster Secret is SECRET-KEY-DATA for SSLv2
        clientMasterKeyMessage.getComputations().setPremasterSecret(Modifiable.explicit(secretKey));

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.SSL2_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(clientMasterKeyMessage));
        trace.addTlsAction(new ReceiveAction(new SSL2ServerVerifyMessage()));
        State state = new State(config, trace);
        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();

        if (!WorkflowTraceResultUtil.didReceiveMessage(trace, SSL2MessageType.SSL_SERVER_HELLO)) {
            return DrownVulnerabilityType.NONE;
        }

        SSL2ServerVerifyMessage serverVerifyMessage =
                (SSL2ServerVerifyMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                trace, SSL2MessageType.SSL_SERVER_VERIFY);
        if (serverVerifyMessage != null) {
            LeakyExportCheckData checkData =
                    new LeakyExportCheckData(
                            state.getTlsContext(), clientMasterKeyMessage, serverVerifyMessage);
            try {
                FileOutputStream fileStream = new FileOutputStream(dataFilePath);
                ObjectOutputStream objectStream = new ObjectOutputStream(fileStream);
                objectStream.writeObject(checkData);
                objectStream.close();
                fileStream.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        return DrownVulnerabilityType.UNKNOWN;
    }

    /**
     * Checks whether the server is affected by the "leaky export" oracle bug (CVE-2016-0704) based
     * on data from genLeakyExportCheckData(). The bug allows to distinguish between an invalid
     * ENCRYPTED-KEY-DATA ciphertext and a valid ciphertext decrypting to a message of the wrong
     * length. This method performs brute-force computations and may take some time to run. It does
     * not connect ot any remote hosts and can run completely offline.
     *
     * @param dataFilePath Name of the data dump file from genLeakyExportCheckData().
     * @return Indication whether the server is vulnerable to the "leaky export" oracle attack
     */
    private DrownVulnerabilityType checkForLeakyExport(Config config, String dataFilePath) {
        LeakyExportCheckData checkData;
        try {
            FileInputStream fileStream = new FileInputStream(dataFilePath);
            ObjectInputStream objectStream = new ObjectInputStream(fileStream);
            checkData = (LeakyExportCheckData) objectStream.readObject();
            objectStream.close();
            fileStream.close();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        LOGGER.debug(
                "Check data read from "
                        + dataFilePath
                        + ", now trying to brute-force server randomness");

        int threadNumber = Runtime.getRuntime().availableProcessors();
        LOGGER.debug("Using " + threadNumber + " threads");
        ExecutorService executor = null;
        ArrayList<LeakyExportCheckCallable> allCallables;
        ArrayList<Future<Boolean>> allResults;
        try {
            executor = Executors.newFixedThreadPool(threadNumber);
            int firstBytesPerThread = 256 / threadNumber;

            allCallables = new ArrayList();
            allResults = new ArrayList();

            for (int i = 0; i < threadNumber; i++) {
                int firstByteFrom = -128 + i * firstBytesPerThread;
                int firstByteTo;
                if (i == threadNumber - 1) {
                    firstByteTo = 128;
                } else {
                    firstByteTo = firstByteFrom + firstBytesPerThread;
                }

                LeakyExportCheckCallable callable =
                        new LeakyExportCheckCallable(firstByteFrom, firstByteTo, checkData);
                allCallables.add(callable);
                allResults.add(executor.submit(callable));
            }

        } finally {
            if (executor != null) {
                executor.shutdown();
            }
        }
        DrownVulnerabilityType vulnerabilityType = DrownVulnerabilityType.SSL2;
        // Count the processed second bytes across all threads to get a quicker
        // and more accurate progress indicator than processing the first bytes
        int processedSecondBytes;

        outer:
        do {
            processedSecondBytes = 0;
            for (LeakyExportCheckCallable callable : allCallables) {
                processedSecondBytes += callable.getProcessedSecondBytes();
            }

            double processedPortion = (double) processedSecondBytes / (double) (256 * 256);
            String processedPercentage = String.format("%.1f", processedPortion * 100);
            LOGGER.debug("Brute-forced approx. {} % so far", processedPercentage);

            for (Future<Boolean> result : allResults) {
                if (result.isDone()) {
                    LOGGER.debug("A thread has finished");
                    try {
                        if (result.get()) {
                            LOGGER.debug("Found server randomness, declaring host vulnerable");
                            vulnerabilityType = DrownVulnerabilityType.SPECIAL;
                            break outer;
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                        LOGGER.warn("Was interrupted - aborting");
                        Thread.currentThread().interrupt();
                        break outer;
                    } catch (ExecutionException e) {
                        throw new RuntimeException(e);
                    }
                }
            }

            try {
                Thread.sleep(60000);
            } catch (InterruptedException e) {
                e.printStackTrace();
                LOGGER.warn("Was interrupted - aborting");
                Thread.currentThread().interrupt();
                break;
            }
        } while (processedSecondBytes < 256 * 256);

        executor.shutdownNow();

        return vulnerabilityType;
    }
}
