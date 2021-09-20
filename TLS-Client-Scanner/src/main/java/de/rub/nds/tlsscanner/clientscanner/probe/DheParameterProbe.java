/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.constants.CompositeModulusType;
import static de.rub.nds.tlsscanner.clientscanner.constants.CompositeModulusType.EVEN;
import static de.rub.nds.tlsscanner.clientscanner.constants.CompositeModulusType.MOD3;
import de.rub.nds.tlsscanner.clientscanner.constants.SmallSubgroupType;
import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.CompositeModulusResult;
import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.SmallSubgroupResult;
import de.rub.nds.tlsscanner.clientscanner.probe.result.DheParameterResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DheParameterProbe extends TlsProbe<ClientReport, DheParameterResult> {

    private static final Logger LOGGER = LogManager.getLogger();

    // Primes with less than two bits (i.e. less than two) don't exist
    private static final int BITLENGTH_CUTOFF_LOWER_BOUND = 2;
    // Performance gets too slow
    private static final int BITLENGTH_CUTOFF_UPPER_BOUND = 8192;

    private Random random;

    private List<CipherSuite> supportedDheCipherSuites;
    private int lowestDheModulusLength;

    public DheParameterProbe(ParallelExecutor parallelExecutor, ScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.DH_PARAMETERS, scannerConfig);
        random = new Random(0);
    }

    @Override
    public DheParameterResult executeTest() {
        lowestDheModulusLength = getLowestDhModSize();
        List<SmallSubgroupResult> smallSubgroupResultList = createSmallSubgroupResultList();
        List<CompositeModulusResult> compositeModulusResultList = createCompositeModulusResultList();
        return new DheParameterResult(lowestDheModulusLength, smallSubgroupResultList, compositeModulusResultList);
    }

    // Implement get highest value

    public int getLowestDhModSize() {
        int lowerBound = BITLENGTH_CUTOFF_LOWER_BOUND;
        int upperBound = BITLENGTH_CUTOFF_UPPER_BOUND;
        do {
            int testValue;

            if ((upperBound - lowerBound / 2) == 0) {
                testValue = lowerBound;
            } else {
                testValue = lowerBound + (upperBound - lowerBound / 2);
            }
            if (testModLength(testValue)) {
                upperBound = testValue;
            } else {
                lowerBound = testValue;
            }
        } while (lowerBound != upperBound);
        return lowerBound;
    }

    private boolean testModLength(int bitLength) {

        Config config = scannerConfig.createConfig();
        config.setDefaultServerSupportedCipherSuites(supportedDheCipherSuites);
        config.setDefaultSelectedCipherSuite(supportedDheCipherSuites.get(0));
        config.setDefaultServerDhModulus(BigInteger.probablePrime(bitLength, random));
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HANDSHAKE,
            RunningModeType.SERVER);
        trace.removeTlsAction(trace.getTlsActions().size() - 1); // remove last action as it is not needed to confirm
                                                                 // success
        State state = new State(config, trace);
        executeState(state);
        return trace.executedAsPlanned();

    }

    private List<CompositeModulusResult> createCompositeModulusResultList() {
        List<CompositeModulusResult> compositeModulusResultList = new LinkedList<>();
        for (CompositeModulusType compositeType : CompositeModulusType.values()) {
            // TODO select proper config here
            Config config = scannerConfig.createConfig();
            config.setDefaultServerSupportedCipherSuites(supportedDheCipherSuites);
            config.setDefaultSelectedCipherSuite(supportedDheCipherSuites.get(0));
            switch (compositeType) {
                case EVEN:
                    config.setDefaultServerDhModulus(createEvenModulus(lowestDheModulusLength));
                    break;
                case MOD3:
                    config.setDefaultServerDhModulus(createModThreeModulus(lowestDheModulusLength));
                    break;
                default:
                    throw new RuntimeException("Failed to generate modulus; unknown type " + compositeType);
            }
            WorkflowTrace trace = new WorkflowConfigurationFactory(config)
                .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
            trace.removeTlsAction(trace.getTlsActions().size() - 1); // remove last action as it is not needed to
                                                                     // confirm success
            State state = new State(config, trace);
            executeState(state);
            if (trace.executedAsPlanned()) {
                compositeModulusResultList.add(new CompositeModulusResult(TestResult.TRUE, compositeType));
            } else {
                compositeModulusResultList.add(new CompositeModulusResult(TestResult.FALSE, compositeType));
                // TODO add different results based on partial failure
            }
        }
        return compositeModulusResultList;
    }

    protected BigInteger createModThreeModulus(int bitLength) {
        BigInteger modulus = BigInteger.probablePrime(bitLength, random);
        while (!modulus.mod(BigInteger.valueOf(3)).equals(BigInteger.ZERO)) {
            modulus = modulus.add(BigInteger.valueOf(2));
        }
        return modulus;
    }

    protected BigInteger createEvenModulus(int bitLength) {
        BigInteger modulus = BigInteger.probablePrime(bitLength, random);
        modulus = modulus.add(BigInteger.ONE);
        return modulus;
    }

    private List<SmallSubgroupResult> createSmallSubgroupResultList() {
        List<SmallSubgroupResult> smallSubgroupResultList = new LinkedList<>();
        for (SmallSubgroupType smallSubgroupType : SmallSubgroupType.values()) {
            // TODO select proper config here
            Config config = scannerConfig.createConfig();
            config.setDefaultServerSupportedCipherSuites(supportedDheCipherSuites);
            config.setDefaultSelectedCipherSuite(supportedDheCipherSuites.get(0));
            switch (smallSubgroupType) {
                case GENERATOR_ONE:
                    config.setDefaultServerDhGenerator(BigInteger.ONE);
                    break;
                case GENERATOR_ZERO:
                    config.setDefaultServerDhGenerator(BigInteger.ZERO);
                    break;
                case MODULUS_ONE:
                    config.setDefaultServerDhGenerator(BigInteger.ONE);
                    break;
                case MODULUS_ZERO:
                    config.setDefaultServerDhGenerator(BigInteger.ZERO);
                    break;
                default:
                    throw new RuntimeException("Failed to generate generator; unknown type " + smallSubgroupType);
            }
            WorkflowTrace trace = new WorkflowConfigurationFactory(config)
                .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
            trace.removeTlsAction(trace.getTlsActions().size() - 1); // remove last action as it is not needed to
                                                                     // confirm success
            State state = new State(config, trace);
            executeState(state);
            if (trace.executedAsPlanned()) {
                smallSubgroupResultList.add(new SmallSubgroupResult(TestResult.TRUE, smallSubgroupType));
            } else {
                smallSubgroupResultList.add(new SmallSubgroupResult(TestResult.FALSE, smallSubgroupType));
                // TODO add different results based on partial failure
            }
        }
        return smallSubgroupResultList;
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return report.getResult(TlsAnalyzedProperty.SUPPORTS_DHE) == TestResult.TRUE;
    }

    @Override
    public DheParameterResult getCouldNotExecuteResult() {
        List<SmallSubgroupResult> subgroupResultList = new LinkedList<>();
        for (SmallSubgroupType type : SmallSubgroupType.values()) {
            subgroupResultList.add(new SmallSubgroupResult(TestResult.CANNOT_BE_TESTED, type));
        }
        List<CompositeModulusResult> compositeResultList = new LinkedList<>();
        for (CompositeModulusType type : CompositeModulusType.values()) {
            compositeResultList.add(new CompositeModulusResult(TestResult.CANNOT_BE_TESTED, type));
        }
        return new DheParameterResult(null, subgroupResultList, compositeResultList);
    }

    @Override
    public void adjustConfig(ClientReport report) {
        List<CipherSuite> ciphers = report.getAdvertisedCipherSuites();
        List<CipherSuite> dheCiphers = new LinkedList<>();
        for (CipherSuite suite : ciphers) {
            if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).name().contains("_DHE_")) {
                dheCiphers.add(suite);
            }
        }
        this.supportedDheCipherSuites = dheCiphers;
    }

}
