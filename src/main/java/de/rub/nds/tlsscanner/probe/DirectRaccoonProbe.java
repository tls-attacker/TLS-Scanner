/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.exception.AttackFailedException;
import de.rub.nds.tlsattacker.attacks.exception.OracleUnstableException;
import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
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
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DirectRaccoonProbe extends TlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private final boolean increasingTimeout = true;

    private final long additionalTimeout = 4000;

    private final long additionalTcpTimeout = 5000;

    private final int mapListDepth = 3;

    private List<VersionSuiteListPair> serverSupportedSuites;

    public DirectRaccoonProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DIRECT_RACCOON, config, 1);
    }

    @Override
    public ProbeResult executeTest() {
        try {

            List<DirectRaccoonCipherSuiteFingerprint> testResultList = new LinkedList<>();
            for (VersionSuiteListPair pair : serverSupportedSuites) {
                if (pair.getVersion() == ProtocolVersion.TLS10 || pair.getVersion() == ProtocolVersion.TLS11 || pair.getVersion() == ProtocolVersion.TLS12) {
                    for (CipherSuite suite : pair.getCiphersuiteList()) {
                        if (suite.usesDH() && CipherSuite.getImplemented().contains(suite)) {
                            boolean normalHandshakeWorking = isNormalHandshakeWorking(pair.getVersion(), suite);
                            DirectRaccoonCipherSuiteFingerprint directRaccoonCipherSuiteFingerprint = getDirectRaccoonCipherSuiteFingerprint(pair.getVersion(), suite);
                            directRaccoonCipherSuiteFingerprint.setHandshakeIsWorking(normalHandshakeWorking);
                            testResultList.add(directRaccoonCipherSuiteFingerprint);
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
            return new DirectRaccoonResponseMap(new LinkedList<DirectRaccoonCipherSuiteFingerprint>(), TestResult.ERROR_DURING_TEST);
        }
    }

    private DirectRaccoonCipherSuiteFingerprint getDirectRaccoonCipherSuiteFingerprint(ProtocolVersion version, CipherSuite suite) {
        Boolean isVulnerable;
        boolean shakyScans = false;
        boolean errornousScans = false;
        EqualityError referenceError = null;

        List<DirectRaccoonVectorResponse> referenceResponseMap = null;
        List<List<DirectRaccoonVectorResponse>> responseMapList = new LinkedList<>();
        try {
            for (int i = 0; i < mapListDepth; i++) {
                List<DirectRaccoonVectorResponse> responseMap = createVectorResponseList(version, suite);
                responseMapList.add(responseMap);
                if (i == 0) {
                    referenceResponseMap = responseMap;
                    referenceError = getEqualityError(responseMap);
                    if (referenceError == EqualityError.NONE) {
                        LOGGER.info("Server appears not vulnerable");
                        break;
                    }
                } else {
                    EqualityError error = getEqualityError(responseMap);
                    if (error == referenceError && lookEqual(referenceResponseMap, responseMap, version, suite)) {
                        CONSOLE.info("Rescan[" + i + "] shows same results");
                    } else {
                        shakyScans = true;
                        CONSOLE.info("Rescan[" + i + "] shows different results");
                    }
                }
            }
        } catch (AttackFailedException E) {
            CONSOLE.info(E.getMessage());
            isVulnerable = null;
        }
        if (shakyScans) {
            isVulnerable = null;
        }
        isVulnerable = referenceError != EqualityError.NONE;
        loop:
        for (List<DirectRaccoonVectorResponse> list : responseMapList) {
            for (DirectRaccoonVectorResponse vector : list) {
                if (vector.isErrorDuringHandshake()) {
                    errornousScans = true;
                    break loop;
                }
            }
        }
        return new DirectRaccoonCipherSuiteFingerprint(isVulnerable, version, suite, responseMapList, referenceError, shakyScans, errornousScans);
    }

    private List<DirectRaccoonVectorResponse> createVectorResponseList(ProtocolVersion version, CipherSuite suite) {
        List<DirectRaccoonVectorResponse> responseList = new LinkedList<>();
        BigInteger initialDhSecret = new BigInteger("4000");
        for (DirectRaccoonWorkflowType type : DirectRaccoonWorkflowType.values()) {
            if (type != DirectRaccoonWorkflowType.INITIAL) {
                LOGGER.info("Version: " + version + "; Ciphersuite: " + suite + "; Type: " + type);
                responseList.add(getVectorResponse(version, suite, type, initialDhSecret, false));
                responseList.add(getVectorResponse(version, suite, type, initialDhSecret, true));
            }
        }
        return responseList;
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

    private DirectRaccoonVectorResponse getVectorResponse(ProtocolVersion version, CipherSuite suite, DirectRaccoonWorkflowType workflowTtype, BigInteger initialClientDhSecret, boolean withNullByte) {
        try {
            Config config = getScannerConfig().createConfig();
            config.setHighestProtocolVersion(version);
            config.setDefaultSelectedProtocolVersion(version);
            config.setDefaultClientSupportedCiphersuites(suite);
            config.setWorkflowExecutorShouldClose(false);
            config.setStopActionsAfterFatal(true);
            config.setStopReceivingAfterFatal(true);
            config.setEarlyStop(true);

            WorkflowTrace trace = DirectRaccoontWorkflowGenerator.generateWorkflowFirstStep(config);

            State state = new State(config, trace);
            executeState(state);

            if (trace.executedAsPlanned()) {
                config.setWorkflowExecutorShouldOpen(false);
                config.setWorkflowExecutorShouldClose(true);
                config.setStopActionsAfterFatal(false);
                config.setStopReceivingAfterFatal(false);
                TlsContext oldTlsContext = state.getTlsContext();
                byte[] clientPublicKey = getClientPublicKey(state.getTlsContext().getServerDhGenerator(), state.getTlsContext().getServerDhModulus(), state.getTlsContext().getServerDhPublicKey(), initialClientDhSecret, withNullByte);
                trace = DirectRaccoontWorkflowGenerator.generateWorkflowSecondStep(config, workflowTtype, clientPublicKey);
                // Execute
                state = new State(config, trace);
                state.replaceTlsContext(oldTlsContext);
                FingerPrintTask fingerPrintTask = new FingerPrintTask(state, additionalTimeout, increasingTimeout, this.getParallelExecutor().getReexecutions(), additionalTcpTimeout);
                this.getParallelExecutor().bulkExecuteTasks(fingerPrintTask);

                // Generate result
                return evaluateFingerPrintTask(version, suite, workflowTtype, withNullByte, fingerPrintTask);
            } else {
                return new DirectRaccoonVectorResponse(null, workflowTtype, version, suite, withNullByte);
            }
        } catch (Exception E) {
            return new DirectRaccoonVectorResponse(null, workflowTtype, version, suite, withNullByte);
        }
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

    private byte[] getClientPublicKey(BigInteger g, BigInteger m, BigInteger serverPublicKey, BigInteger initialClientDhSecret, boolean withNullByte) {
        int length = ArrayConverter.bigIntegerToByteArray(m).length;
        byte[] pms = ArrayConverter.bigIntegerToNullPaddedByteArray(serverPublicKey.modPow(initialClientDhSecret, m), length);
        if (((withNullByte && pms[0] == 0)) || (!withNullByte && pms[0] != 0)) {
            System.out.println("initial secret: " + initialClientDhSecret);
            System.out.println("g:" + (ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(g),false,false).replace(" ", "")));
            System.out.println("m:" + (ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(m),false,false).replace(" ", "")));
            System.out.println("spk:" + (ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(serverPublicKey),false,false).replace(" ", "")));
            System.out.println("shared s:" + ArrayConverter.bytesToHexString(pms, false, false));
            System.out.println("with null:" + m);
            return g.modPow(initialClientDhSecret, m).toByteArray();
        } else {
            initialClientDhSecret = initialClientDhSecret.add(new BigInteger("1"));
            return getClientPublicKey(g, m, serverPublicKey, initialClientDhSecret, withNullByte);
        }
    }

    /**
     *
     * @param responseVectorListOne
     * @param responseVectorListTwo
     * @param testedVersion
     * @param testedSuite
     * @return
     */
    public boolean lookEqual(List<DirectRaccoonVectorResponse> responseVectorListOne, List<DirectRaccoonVectorResponse> responseVectorListTwo, ProtocolVersion testedVersion, CipherSuite testedSuite) {
        boolean result = true;
        if (responseVectorListOne.size() != responseVectorListTwo.size()) {
            throw new OracleUnstableException(
                    "The Oracle seems to be unstable - there is something going terrible wrong. We recommend manual analysis");
        }

        for (DirectRaccoonVectorResponse vectorResponseOne : responseVectorListOne) {
            // Find equivalent
            DirectRaccoonVectorResponse equivalentVector = null;
            for (DirectRaccoonVectorResponse vectorResponseTwo : responseVectorListTwo) {
                if (vectorResponseOne.getWorkflowType().equals(vectorResponseTwo.getWorkflowType()) && vectorResponseOne.isPmsWithNullybte() == (vectorResponseTwo.isPmsWithNullybte())) {
                    equivalentVector = vectorResponseTwo;
                    break;
                }
            }
            if (vectorResponseOne.getFingerprint() == null) {
                LOGGER.error("First vector has no fingerprint:" + testedSuite + " - " + testedVersion);
                vectorResponseOne.setErrorDuringHandshake(true);
                result = false;
                continue;
            }
            if (equivalentVector == null) {
                LOGGER.error("Equivalent vector is null:" + testedSuite + " - " + testedVersion);
                result = false;
                vectorResponseOne.setMissingEquivalent(true);
                continue;
            }
            if (equivalentVector.getFingerprint() == null) {
                LOGGER.warn("Equivalent vector has no fingerprint:" + testedSuite + " - " + testedVersion);
                equivalentVector.setErrorDuringHandshake(true);
                result = false;
                continue;
            }

            EqualityError error = FingerPrintChecker.checkEquality(vectorResponseOne.getFingerprint(),
                    equivalentVector.getFingerprint(), true);
            if (error != EqualityError.NONE) {
                LOGGER.warn("There is an error beween rescan:" + error + " - " + testedSuite + " - " + testedVersion);
                result = false;
                vectorResponseOne.setShaky(true);
            }
        }
        return result;
    }

    /**
     *
     * @param responseVectorList
     * @return
     */
    public EqualityError getEqualityError(List<DirectRaccoonVectorResponse> responseVectorList) {
        for (DirectRaccoonVectorResponse responseOne : responseVectorList) {
            for (DirectRaccoonVectorResponse responseTwo : responseVectorList) {
                // Compare pairs with and without nullbyte
                if (responseOne == responseTwo || responseOne.getWorkflowType() != responseTwo.getWorkflowType()) {
                    continue;
                }
                boolean shouldCompare = true;
                if (responseOne.getFingerprint() == null) {
                    responseOne.setErrorDuringHandshake(true);
                    shouldCompare = false;
                }
                if (responseTwo.getFingerprint() == null) {
                    responseOne.setErrorDuringHandshake(true);
                    shouldCompare = false;
                }
                if (shouldCompare) {
                    EqualityError error = FingerPrintChecker.checkEquality(responseOne.getFingerprint(),
                            responseTwo.getFingerprint(), true);
                    if (error != EqualityError.NONE) {
                        CONSOLE.info("Found an EqualityError: " + error);
                        LOGGER.debug("Fingerprint1: " + responseOne.getFingerprint().toString());
                        LOGGER.debug("Fingerprint2: " + responseTwo.getFingerprint().toString());
                        return error;
                    }
                }
            }
        }
        return EqualityError.NONE;
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
