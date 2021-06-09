/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.leak.info.DirectRaccoonOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.directraccoon.DirectRaccoonVector;
import de.rub.nds.tlsscanner.serverscanner.probe.directraccoon.DirectRaccoonWorkflowGenerator;
import de.rub.nds.tlsscanner.serverscanner.probe.directraccoon.DirectRaccoonWorkflowType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.DirectRaccoonResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.InformationLeakTest;
import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DirectRaccoonProbe extends TlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private final int iterationsPerHandshake = 3;
    private final int additionalIterationsPerHandshake = 97;

    private List<VersionSuiteListPair> serverSupportedSuites;

    public DirectRaccoonProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DIRECT_RACCOON, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<InformationLeakTest<DirectRaccoonOracleTestInfo>> testResultList = new LinkedList<>();
            loop: for (VersionSuiteListPair pair : serverSupportedSuites) {
                if (pair.getVersion() == ProtocolVersion.SSL3 || pair.getVersion() == ProtocolVersion.TLS10
                    || pair.getVersion() == ProtocolVersion.TLS11 || pair.getVersion() == ProtocolVersion.TLS12) {
                    for (CipherSuite suite : pair.getCipherSuiteList()) {
                        if (suite.usesDH() && CipherSuite.getImplemented().contains(suite)) {
                            InformationLeakTest<DirectRaccoonOracleTestInfo> informationLeakTest =
                                createDirectRaccoonInformationLeakTest(pair.getVersion(), suite,
                                    DirectRaccoonWorkflowType.CKE_CCS_FIN);
                            testResultList.add(informationLeakTest);

                        }
                    }
                }
            }
            return new DirectRaccoonResult(testResultList);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new DirectRaccoonResult(TestResult.ERROR_DURING_TEST);
        }
    }

    private InformationLeakTest<DirectRaccoonOracleTestInfo> createDirectRaccoonInformationLeakTest(
        ProtocolVersion version, CipherSuite suite, DirectRaccoonWorkflowType workflowType) {

        List<VectorResponse> responseMap =
            createVectorResponseList(version, suite, workflowType, iterationsPerHandshake);
        InformationLeakTest<DirectRaccoonOracleTestInfo> informationLeakTest =
            new InformationLeakTest<>(new DirectRaccoonOracleTestInfo(suite, version, workflowType), responseMap);

        if (informationLeakTest.isDistinctAnswers()) {
            LOGGER.debug("Found non identical answers, performing " + iterationsPerHandshake + " additional tests");
            responseMap = createVectorResponseList(version, suite, workflowType, additionalIterationsPerHandshake);
            informationLeakTest.extendTestWithVectorResponses(responseMap);
        }
        return informationLeakTest;
    }

    private List<VectorResponse> createVectorResponseList(ProtocolVersion version, CipherSuite suite,
        DirectRaccoonWorkflowType type, int numberOfExecutionsEach) {
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

    private List<VectorResponse> getVectorResponseList(ProtocolVersion version, CipherSuite suite,
        DirectRaccoonWorkflowType workflowType, BigInteger initialClientDhSecret, List<Boolean> withNullByteList) {
        List<TlsTask> taskList = new LinkedList<>();
        for (Boolean nullByte : withNullByteList) {
            Config config = getScannerConfig().createConfig();
            config.setHighestProtocolVersion(version);
            config.setDefaultSelectedProtocolVersion(version);
            config.setDefaultClientSupportedCipherSuites(suite);
            config.setDefaultSelectedCipherSuite(suite);
            config.setAddECPointFormatExtension(false);
            config.setAddEllipticCurveExtension(false);
            config.setAddRenegotiationInfoExtension(true);
            config.setAddSignatureAndHashAlgorithmsExtension(true);

            config.setWorkflowExecutorShouldClose(false);
            config.setStopActionsAfterFatal(false);
            config.setStopReceivingAfterFatal(false);
            config.setStopActionsAfterIOException(true);
            config.setEarlyStop(true);
            config.setQuickReceive(true);

            WorkflowTrace trace =
                DirectRaccoonWorkflowGenerator.generateWorkflow(config, workflowType, initialClientDhSecret, nullByte);
            // Store
            trace.setName("" + nullByte);
            State state = new State(config, trace);

            FingerPrintTask fingerPrintTask = new FingerPrintTask(state, 1);
            initialClientDhSecret = initialClientDhSecret.add(new BigInteger("" + 20000));
            taskList.add(fingerPrintTask);
        }
        this.getParallelExecutor().bulkExecuteTasks(taskList);
        List<VectorResponse> responseList = new LinkedList<>();
        for (TlsTask task : taskList) {
            FingerPrintTask fingerPrintTask = (FingerPrintTask) task;
            Boolean nullByte = Boolean.parseBoolean(fingerPrintTask.getState().getWorkflowTrace().getName());
            VectorResponse vectorResponse =
                evaluateFingerPrintTask(version, suite, workflowType, nullByte, fingerPrintTask);
            if (vectorResponse != null) {
                responseList.add(vectorResponse);
            }
        }
        // Generate result
        return responseList;
    }

    private VectorResponse evaluateFingerPrintTask(ProtocolVersion version, CipherSuite suite,
        DirectRaccoonWorkflowType workflowType, boolean withNullByte, FingerPrintTask fingerPrintTask) {
        DirectRaccoonVector raccoonVector = new DirectRaccoonVector(workflowType, version, suite, withNullByte);
        if (fingerPrintTask.isHasError()) {
            LOGGER.warn("Could not extract fingerprint for WorkflowType=" + type + ", version=" + version + ", suite="
                + suite + ", pmsWithNullByte=" + withNullByte + ";");
            return null;
        } else {
            return new VectorResponse(raccoonVector, fingerPrintTask.getFingerprint());
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (!(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_SSL_3), TestResult.TRUE))
            && !(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0), TestResult.TRUE))
            && !(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1), TestResult.TRUE))
            && !(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2), TestResult.TRUE))) {
            return false;
        }
        if (report.getCipherSuites() == null) {
            return false;
        }
        return Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_DH), TestResult.TRUE);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        serverSupportedSuites = report.getVersionSuitePairs();
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new DirectRaccoonResult(TestResult.COULD_NOT_TEST);
    }
}
