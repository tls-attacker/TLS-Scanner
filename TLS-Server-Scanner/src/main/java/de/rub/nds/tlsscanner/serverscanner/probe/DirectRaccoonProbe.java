/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.task.FingerPrintTask;
import de.rub.nds.tlsscanner.core.vector.VectorResponse;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.leak.DirectRaccoonOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.directraccoon.DirectRaccoonVector;
import de.rub.nds.tlsscanner.serverscanner.probe.directraccoon.DirectRaccoonWorkflowGenerator;
import de.rub.nds.tlsscanner.serverscanner.probe.directraccoon.DirectRaccoonWorkflowType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DirectRaccoonProbe extends TlsServerProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int ITERATIONS_PER_HANDSHAKE = 3;
    private static final int ADDITIONAL_ITERATIONS_PER_HANDSHAKE = 97;

    private List<VersionSuiteListPair> serverSupportedSuites;
    private List<InformationLeakTest<DirectRaccoonOracleTestInfo>> testResultList =
            new LinkedList<>();

    private TestResult vulnerable = TestResults.COULD_NOT_TEST;

    public DirectRaccoonProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DIRECT_RACCOON, configSelector);
        register(
                TlsAnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON,
                TlsAnalyzedProperty.DIRECT_RACCOON_TEST_RESULT);
    }

    @Override
    protected void executeTest() {
        testResultList = new LinkedList<>();
        for (VersionSuiteListPair pair : serverSupportedSuites) {
            if (!pair.getVersion().isTLS13() && pair.getVersion() != ProtocolVersion.SSL2) {
                for (CipherSuite suite : pair.getCipherSuiteList()) {
                    if (suite.usesDH() && CipherSuite.getImplemented().contains(suite)) {
                        InformationLeakTest<DirectRaccoonOracleTestInfo> informationLeakTest =
                                createDirectRaccoonInformationLeakTest(
                                        pair.getVersion(), suite, DirectRaccoonWorkflowType.CKE);
                        testResultList.add(informationLeakTest);
                    }
                }
            }
        }
        vulnerable = TestResults.FALSE;
        for (InformationLeakTest<DirectRaccoonOracleTestInfo> informationLeakTest :
                testResultList) {
            if (informationLeakTest.isSignificantDistinctAnswers()) {
                vulnerable = TestResults.TRUE;
            }
        }
    }

    private InformationLeakTest<DirectRaccoonOracleTestInfo> createDirectRaccoonInformationLeakTest(
            ProtocolVersion version, CipherSuite suite, DirectRaccoonWorkflowType workflowType) {

        List<VectorResponse> responseMap =
                createVectorResponseList(version, suite, workflowType, ITERATIONS_PER_HANDSHAKE);
        InformationLeakTest<DirectRaccoonOracleTestInfo> informationLeakTest =
                new InformationLeakTest<>(
                        new DirectRaccoonOracleTestInfo(suite, version, workflowType), responseMap);

        if (informationLeakTest.isDistinctAnswers()) {
            LOGGER.debug(
                    "Found non identical answers, performing "
                            + ITERATIONS_PER_HANDSHAKE
                            + " additional tests");
            responseMap =
                    createVectorResponseList(
                            version, suite, workflowType, ADDITIONAL_ITERATIONS_PER_HANDSHAKE);
            informationLeakTest.extendTestWithVectorResponses(responseMap);
        }
        return informationLeakTest;
    }

    private List<VectorResponse> createVectorResponseList(
            ProtocolVersion version,
            CipherSuite suite,
            DirectRaccoonWorkflowType type,
            int numberOfExecutionsEach) {
        Random r = new Random();
        BigInteger initialDhSecret = new BigInteger("" + (r.nextInt()));
        List<Boolean> booleanList = new LinkedList<>();
        for (int i = 0; i < numberOfExecutionsEach; i++) {
            booleanList.add(true);
            booleanList.add(false);
        }
        Collections.shuffle(booleanList);
        return getVectorResponseList(version, suite, type, initialDhSecret, booleanList);
    }

    private List<VectorResponse> getVectorResponseList(
            ProtocolVersion version,
            CipherSuite suite,
            DirectRaccoonWorkflowType workflowType,
            BigInteger initialClientDhSecret,
            List<Boolean> withNullByteList) {
        List<TlsTask> taskList = new LinkedList<>();
        for (Boolean nullByte : withNullByteList) {
            Config config = configSelector.getBaseConfig();
            config.setHighestProtocolVersion(version);
            config.setDefaultClientSupportedCipherSuites(suite);
            config.setWorkflowExecutorShouldClose(false);
            config.setStopActionsAfterWarning(false);
            config.setStopActionsAfterFatal(false);
            config.setStopReceivingAfterFatal(false);
            WorkflowTrace trace =
                    DirectRaccoonWorkflowGenerator.generateWorkflow(
                            config, workflowType, initialClientDhSecret, nullByte);
            // Store
            trace.setName("" + nullByte);
            State state = new State(config, trace);

            FingerPrintTask fingerPrintTask = new FingerPrintTask(state, 1);
            initialClientDhSecret = initialClientDhSecret.add(new BigInteger("" + 20000));
            taskList.add(fingerPrintTask);
        }
        getParallelExecutor().bulkExecuteTasks(taskList);
        List<VectorResponse> responseList = new LinkedList<>();
        for (TlsTask task : taskList) {
            FingerPrintTask fingerPrintTask = (FingerPrintTask) task;
            Boolean nullByte =
                    Boolean.parseBoolean(fingerPrintTask.getState().getWorkflowTrace().getName());
            VectorResponse vectorResponse =
                    evaluateFingerPrintTask(
                            version, suite, workflowType, nullByte, fingerPrintTask);
            if (vectorResponse != null) {
                responseList.add(vectorResponse);
            }
        }
        return responseList;
    }

    private VectorResponse evaluateFingerPrintTask(
            ProtocolVersion version,
            CipherSuite suite,
            DirectRaccoonWorkflowType workflowType,
            boolean withNullByte,
            FingerPrintTask fingerPrintTask) {
        DirectRaccoonVector raccoonVector =
                new DirectRaccoonVector(workflowType, version, suite, withNullByte);
        if (fingerPrintTask.isHasError()) {
            LOGGER.warn(
                    "Could not extract fingerprint for WorkflowType="
                            + workflowType
                            + ", version="
                            + version
                            + ", suite="
                            + suite
                            + ", pmsWithNullByte="
                            + withNullByte
                            + ";");
            return null;
        } else {
            return new VectorResponse(raccoonVector, fingerPrintTask.getFingerprint());
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(TlsProbeType.CIPHER_SUITE)
                .and(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_DHE))
                .and(
                        new PropertyTrueRequirement<ServerReport>(
                                        TlsAnalyzedProperty.SUPPORTS_SSL_3)
                                .or(
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_0))
                                .or(
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_1))
                                .or(
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2))
                                .or(
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_DTLS_1_0))
                                .or(
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_DTLS_1_2)));
    }

    @Override
    public void adjustConfig(ServerReport report) {
        serverSupportedSuites = report.getVersionSuitePairs();
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.DIRECT_RACCOON_TEST_RESULT, testResultList);
        put(TlsAnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON, vulnerable);
    }
}
