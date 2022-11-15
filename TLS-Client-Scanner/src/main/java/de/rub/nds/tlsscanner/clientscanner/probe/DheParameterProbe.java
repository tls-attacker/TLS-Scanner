/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.constants.CompositeModulusType;
import de.rub.nds.tlsscanner.clientscanner.constants.PrimeModulus;
import de.rub.nds.tlsscanner.clientscanner.constants.SmallSubgroupType;
import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.CompositeModulusResult;
import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.SmallSubgroupResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.PropertyRequirement;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
<<<<<<< HEAD

public class DheParameterProbe extends TlsClientProbe<ClientScannerConfig, ClientReport> {

    // Primes with less than two bits (i.e. less than two) don't exist
    private static final int BITLENGTH_CUTOFF_LOWER_BOUND = 2;
    // Performance gets too slow
    private static final int BITLENGTH_CUTOFF_UPPER_BOUND = 8192;

    private Random random;

    private List<SmallSubgroupResult> smallSubgroupResults;
    private List<CompositeModulusResult> compositeModulusResultList;
    private List<CipherSuite> supportedDheCipherSuites;
    private Integer lowestDheModulusLength;

    public DheParameterProbe(ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.DH_PARAMETERS, scannerConfig);
        register(TlsAnalyzedProperty.SMALL_DHE_SUBGROUP_RESULTS, TlsAnalyzedProperty.COMPOSITE_DHE_MODULUS_RESULTS);
=======
import javax.swing.SortOrder;

public class DheParameterProbe
        extends TlsClientProbe<ClientScannerConfig, ClientReport, DheParameterResult> {

    private final Random random;
    private final List<PrimeModulus> primeModuli;
    private List<CipherSuite> supportedDheCipherSuites;
    private Integer lowestDheModulusLength;
    private Integer highestDheModulusLength;

    public DheParameterProbe(ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.DHE_PARAMETERS, scannerConfig);
>>>>>>> master
        random = new Random(0);
        primeModuli = Arrays.asList(PrimeModulus.values());
    }

    @Override
<<<<<<< HEAD
    public void executeTest() {
        lowestDheModulusLength = getLowestDhModSize();
        smallSubgroupResults = createSmallSubgroupResultList();
        compositeModulusResultList = createCompositeModulusResultList();
    }

    // Implement get highest value
    public int getLowestDhModSize() {
        int lowerBound = BITLENGTH_CUTOFF_LOWER_BOUND;
        int upperBound = BITLENGTH_CUTOFF_UPPER_BOUND;
        do {
            int testValue = lowerBound + ((upperBound - lowerBound) / 2);
            if (testModLength(testValue)) {
                upperBound = testValue;
            } else {
                lowerBound = testValue;
=======
    public DheParameterResult executeTest() {
        PrimeModulus.sort(primeModuli, SortOrder.ASCENDING);
        lowestDheModulusLength = getFirstAcceptedModulus(primeModuli);
        PrimeModulus.sort(primeModuli, SortOrder.DESCENDING);
        highestDheModulusLength = getFirstAcceptedModulus(primeModuli);
        List<SmallSubgroupResult> smallSubgroupResultList = createSmallSubgroupResultList();
        List<CompositeModulusResult> compositeModulusResultList =
                createCompositeModulusResultList();

        return new DheParameterResult(
                lowestDheModulusLength,
                highestDheModulusLength,
                smallSubgroupResultList,
                compositeModulusResultList);
    }

    private Integer getFirstAcceptedModulus(List<PrimeModulus> primeModuli) {
        for (PrimeModulus modulus : primeModuli) {
            Config config = scannerConfig.createConfig();
            config.setDefaultServerSupportedCipherSuites(supportedDheCipherSuites);
            config.setDefaultServerDhModulus(modulus.getModulus());
            if (testConfig(config)) {
                return modulus.getBitLength();
>>>>>>> master
            }
        }
        return null;
    }

<<<<<<< HEAD
    private boolean testModLength(int bitLength) {

        Config config = scannerConfig.createConfig();
        config.setDefaultServerSupportedCipherSuites(supportedDheCipherSuites);
        config.setDefaultSelectedCipherSuite(supportedDheCipherSuites.get(0));
        config.setDefaultServerDhModulus(BigInteger.probablePrime(bitLength, random));
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HANDSHAKE,
            RunningModeType.SERVER);
        trace.removeTlsAction(trace.getTlsActions().size() - 1); // remove last action as it is not needed to confirm
        // success
=======
    private boolean testConfig(Config config) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
>>>>>>> master
        State state = new State(config, trace);
        executeState(state);
        return trace.executedAsPlanned();
    }

    private List<CompositeModulusResult> createCompositeModulusResultList() {
        List<CompositeModulusResult> compositeModulusResultList = new LinkedList<>();
        for (CompositeModulusType compositeType : CompositeModulusType.values()) {
            Config config = scannerConfig.createConfig();
            config.setDefaultServerSupportedCipherSuites(supportedDheCipherSuites);
            switch (compositeType) {
                case EVEN:
                    config.setDefaultServerDhModulus(createEvenModulus(lowestDheModulusLength));
                    break;
                case MOD3:
                    config.setDefaultServerDhModulus(createModThreeModulus(lowestDheModulusLength));
                    break;
                default:
                    break;
            }
<<<<<<< HEAD
            WorkflowTrace trace = new WorkflowConfigurationFactory(config)
                .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
            trace.removeTlsAction(trace.getTlsActions().size() - 1); // remove last action as it is not needed to
            // confirm success
            State state = new State(config, trace);
            executeState(state);
            if (trace.executedAsPlanned()) {
                compositeModulusResultList.add(new CompositeModulusResult(TestResults.TRUE, compositeType));
=======
            if (testConfig(config)) {
                compositeModulusResultList.add(
                        new CompositeModulusResult(TestResults.TRUE, compositeType));
>>>>>>> master
            } else {
                compositeModulusResultList.add(
                        new CompositeModulusResult(TestResults.FALSE, compositeType));
            }
        }
        return compositeModulusResultList;
    }

    private BigInteger createModThreeModulus(int bitLength) {
        BigInteger modulus = BigInteger.probablePrime(bitLength, random);
        while (!modulus.mod(BigInteger.valueOf(3)).equals(BigInteger.ZERO)) {
            modulus = modulus.add(BigInteger.valueOf(2));
        }
        return modulus;
    }

    private BigInteger createEvenModulus(int bitLength) {
        BigInteger modulus = BigInteger.probablePrime(bitLength, random);
        // we xor here to ensure the modulus will be even (was odd), but keeps the same bit length
        modulus = modulus.xor(BigInteger.ONE);
        return modulus;
    }

    private List<SmallSubgroupResult> createSmallSubgroupResultList() {
        List<SmallSubgroupResult> smallSubgroupResultList = new LinkedList<>();
        for (SmallSubgroupType smallSubgroupType : SmallSubgroupType.values()) {
            Config config = scannerConfig.createConfig();
            config.setDefaultServerSupportedCipherSuites(supportedDheCipherSuites);
            switch (smallSubgroupType) {
                case GENERATOR_ONE:
                    config.setDefaultServerDhGenerator(BigInteger.ONE);
                    break;
                case MODULUS_ONE:
                    config.setDefaultServerDhModulus(BigInteger.ONE);
                    break;
                default:
                    break;
            }
<<<<<<< HEAD
            WorkflowTrace trace = new WorkflowConfigurationFactory(config)
                .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
            trace.removeTlsAction(trace.getTlsActions().size() - 1); // remove last action as it is not needed to
            // confirm success
            State state = new State(config, trace);
            executeState(state);
            if (trace.executedAsPlanned()) {
                smallSubgroupResultList.add(new SmallSubgroupResult(TestResults.TRUE, smallSubgroupType));
=======
            if (testConfig(config)) {
                smallSubgroupResultList.add(
                        new SmallSubgroupResult(TestResults.TRUE, smallSubgroupType));
>>>>>>> master
            } else {
                smallSubgroupResultList.add(
                        new SmallSubgroupResult(TestResults.FALSE, smallSubgroupType));
            }
        }
        return smallSubgroupResultList;
    }

    @Override
<<<<<<< HEAD
    public void adjustConfig(ClientReport report) {
        List<CipherSuite> ciphers = report.getClientAdvertisedCiphersuites();
        List<CipherSuite> dheCiphers = new LinkedList<>();
        for (CipherSuite suite : ciphers) {
            if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).name().contains("_DHE_")) {
                dheCiphers.add(suite);
            }
        }
        supportedDheCipherSuites = dheCiphers;
    }

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.COMPOSITE_DHE_MODULUS_RESULTS, compositeModulusResultList);
        put(TlsAnalyzedProperty.SMALL_DHE_SUBGROUP_RESULTS, smallSubgroupResults);
        report.setLowestPossibleDheModulusSize(lowestDheModulusLength);
    }

    @Override
    protected Requirement getRequirements() {
        return new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_DHE);
    }
=======
    public boolean canBeExecuted(ClientReport report) {
        return report.isProbeAlreadyExecuted(TlsProbeType.CIPHER_SUITE)
                && (report.getResult(TlsAnalyzedProperty.SUPPORTS_DHE) == TestResults.TRUE);
    }

    @Override
    public DheParameterResult getCouldNotExecuteResult() {
        return new DheParameterResult(null, null, null, null);
    }

    @Override
    public void adjustConfig(ClientReport report) {
        supportedDheCipherSuites = new LinkedList<>();
        for (CipherSuite suite : report.getCipherSuites()) {
            if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeDhe()) {
                supportedDheCipherSuites.add(suite);
            }
        }
    }
>>>>>>> master
}
