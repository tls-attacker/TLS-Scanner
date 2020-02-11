/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.DirectRaccoonResponseMap;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.probe.directRaccoon.DirectRaccoonCipherSuiteFingerprint;
import de.rub.nds.tlsscanner.probe.directRaccoon.DirectRaccoontWorkflowGenerator;
import de.rub.nds.tlsscanner.probe.directRaccoon.DirectRaccoonWorkflowType;
import de.rub.nds.tlsscanner.probe.directRaccoon.DirectRaccoonVectorResponse;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
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

    private final int iterationsPerHandshake = 50;

    private List<VersionSuiteListPair> serverSupportedSuites;

    public DirectRaccoonProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DIRECT_RACCOON, config, 1);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<DirectRaccoonCipherSuiteFingerprint> testResultList = new LinkedList<>();
            loop:
            for (VersionSuiteListPair pair : serverSupportedSuites) {
                if (pair.getVersion() == ProtocolVersion.TLS10 || pair.getVersion() == ProtocolVersion.TLS11 || pair.getVersion() == ProtocolVersion.TLS12) {
                    for (CipherSuite suite : pair.getCiphersuiteList()) {
                        if (suite.usesDH() && CipherSuite.getImplemented().contains(suite)) {
                            for (DirectRaccoonWorkflowType workflowType : DirectRaccoonWorkflowType.values()) {
                                if (workflowType == DirectRaccoonWorkflowType.INITIAL) {
                                    continue;
                                }
                                boolean normalHandshakeWorking = isNormalHandshakeWorking(pair.getVersion(), suite);
                                DirectRaccoonCipherSuiteFingerprint directRaccoonCipherSuiteFingerprint = getDirectRaccoonCipherSuiteFingerprint(pair.getVersion(), suite, workflowType);
                                directRaccoonCipherSuiteFingerprint.setHandshakeIsWorking(normalHandshakeWorking);
                                testResultList.add(directRaccoonCipherSuiteFingerprint);
                            }
                        }
                    }
                }
            }
            for (DirectRaccoonCipherSuiteFingerprint fingerprint : testResultList) {
                if (Objects.equals(fingerprint.getVulnerable(), Boolean.TRUE)) {
                    return new DirectRaccoonResponseMap(testResultList, TestResult.TRUE);
                }
            }
            return new DirectRaccoonResponseMap(testResultList, TestResult.FALSE);
        } catch (Exception e) {
            LOGGER.error("Error", e);
            return new DirectRaccoonResponseMap(new LinkedList<>(), TestResult.ERROR_DURING_TEST);
        }
    }

    private DirectRaccoonCipherSuiteFingerprint getDirectRaccoonCipherSuiteFingerprint(ProtocolVersion version, CipherSuite suite, DirectRaccoonWorkflowType workflowType) {
        boolean errornousScans = false;
        EqualityError referenceError = null;

        List<DirectRaccoonVectorResponse> responseMap = createVectorResponseList(version, suite, workflowType, iterationsPerHandshake);

        Boolean vulnerable = true; //TODO Check if the server is vulnerable 

        for (DirectRaccoonVectorResponse vector : responseMap) {
            if (vector.isErrorDuringHandshake()) {
                errornousScans = true;
                break;
            }
        }
        return new DirectRaccoonCipherSuiteFingerprint(vulnerable, version, suite, workflowType, responseMap, referenceError, errornousScans);
    }

    private List<DirectRaccoonVectorResponse> createVectorResponseList(ProtocolVersion version, CipherSuite suite, DirectRaccoonWorkflowType type, int numberOfExecutionsEach) {
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

    private boolean isNormalHandshakeWorking(ProtocolVersion version, CipherSuite suite) {
        try {
            Config config = getScannerConfig().createConfig();
            config.setHighestProtocolVersion(version);
            config.setDefaultSelectedProtocolVersion(version);
            config.setDefaultClientSupportedCiphersuites(suite);
            config.setStopActionsAfterFatal(true);
            config.setStopReceivingAfterFatal(true);
            config.setEarlyStop(true);
            WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
            State state = new State(config, trace);
            executeState(state);
            return state.getWorkflowTrace().executedAsPlanned();
        } catch (Exception E) {
            LOGGER.warn("Could not perform initial handshake", E);
            return false;
        }
    }

    private List<DirectRaccoonVectorResponse> getVectorResponseList(ProtocolVersion version, CipherSuite suite, DirectRaccoonWorkflowType workflowType, BigInteger initialClientDhSecret, List<Boolean> withNullByteList) {
        List<TlsTask> taskList = new LinkedList<>();
        for (Boolean nullByte : withNullByteList) {
            Config config = getScannerConfig().createConfig();
            config.setHighestProtocolVersion(version);
            config.setDefaultSelectedProtocolVersion(version);
            config.setDefaultClientSupportedCiphersuites(suite);
            config.setWorkflowExecutorShouldClose(false);
            config.setStopActionsAfterFatal(false);
            config.setStopReceivingAfterFatal(false);
            config.setEarlyStop(true);

            WorkflowTrace trace = DirectRaccoontWorkflowGenerator.generateWorkflow(config, workflowType, initialClientDhSecret, nullByte);
            //Store 
            trace.setName("" + nullByte);
            State state = new State(config, trace);

            FingerPrintTask fingerPrintTask = new FingerPrintTask(state, 1);
            taskList.add(fingerPrintTask);
        }
        this.getParallelExecutor().bulkExecuteTasks(taskList);
        List<DirectRaccoonVectorResponse> responseList = new LinkedList<>();
        for (TlsTask task : taskList) {
            FingerPrintTask fingerPrintTask = (FingerPrintTask) task;
            Boolean nullByte = Boolean.parseBoolean(fingerPrintTask.getState().getWorkflowTrace().getName());
            responseList.add(evaluateFingerPrintTask(version, suite, workflowType, nullByte, fingerPrintTask));
        }
        // Generate result
        return responseList;
    }

    private DirectRaccoonVectorResponse evaluateFingerPrintTask(ProtocolVersion version, CipherSuite suite, DirectRaccoonWorkflowType workflowType, boolean withNullByte, FingerPrintTask fingerPrintTask) {
        DirectRaccoonVectorResponse vectorResponse = null;
        if (fingerPrintTask.isHasError()) {
            LOGGER.warn("Could not extract fingerprint for WorkflowType=" + type + ", version="
                    + version + ", suite=" + suite + ", pmsWithNullByte=" + withNullByte + ";");
            vectorResponse = new DirectRaccoonVectorResponse(null, workflowType, version, suite, withNullByte);
            vectorResponse.setErrorDuringHandshake(true);
        } else {
            vectorResponse = new DirectRaccoonVectorResponse(fingerPrintTask.getFingerprint(), workflowType, version, suite, withNullByte);
        }
        return vectorResponse;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (!(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0), TestResult.TRUE)) && !(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1), TestResult.TRUE)) && !(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2), TestResult.TRUE))) {
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
        return new DirectRaccoonResponseMap(null, TestResult.COULD_NOT_TEST);
    }
}
