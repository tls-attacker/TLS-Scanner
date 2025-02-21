/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResults;
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
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import javax.swing.SortOrder;

public class DheParameterProbe extends TlsClientProbe {

    private Random random;

    private List<SmallSubgroupResult> smallSubgroupResults = null;
    private List<CompositeModulusResult> compositeModulusResultList = null;
    private HashMap<CompositeModulusType, TlsAnalyzedProperty>
            compositeModulusTypeToPropertyMapping;
    private HashMap<SmallSubgroupType, TlsAnalyzedProperty> smallSubgroupTypeToPropertyMapping;
    private List<CipherSuite> supportedDheCipherSuites;
    private final List<PrimeModulus> primeModuli;
    private Integer lowestDheModulusLength = null;
    private Integer highestDheModulusLength = null;

    public DheParameterProbe(ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.DHE_PARAMETERS, scannerConfig);
        register(
                TlsAnalyzedProperty.SUPPORTS_MODULUS_ONE,
                TlsAnalyzedProperty.SUPPORTS_MODULUS_ZERO,
                TlsAnalyzedProperty.SUPPORTS_GENERATOR_ONE,
                TlsAnalyzedProperty.SUPPORTS_GENERATOR_ZERO,
                TlsAnalyzedProperty.SUPPORTS_MOD3_MODULUS,
                TlsAnalyzedProperty.SUPPORTS_EVEN_MODULUS,
                TlsAnalyzedProperty.LOWEST_POSSIBLE_DHE_MODULUS_SIZE,
                TlsAnalyzedProperty.HIGHEST_POSSIBLE_DHE_MODULUS_SIZE);

        random = new Random(0);
        primeModuli = Arrays.asList(PrimeModulus.values());
        compositeModulusTypeToPropertyMapping = getCompositeModulusTypeMap();
        smallSubgroupTypeToPropertyMapping = getSmallSubgroupTypeMap();
    }

    @Override
    protected void executeTest() {
        PrimeModulus.sort(primeModuli, SortOrder.ASCENDING);
        lowestDheModulusLength = getFirstAcceptedModulus(primeModuli);
        PrimeModulus.sort(primeModuli, SortOrder.DESCENDING);
        highestDheModulusLength = getFirstAcceptedModulus(primeModuli);
        smallSubgroupResults = createSmallSubgroupResultList();
        compositeModulusResultList = createCompositeModulusResultList();
    }

    private Integer getFirstAcceptedModulus(List<PrimeModulus> primeModuli) {
        for (PrimeModulus modulus : primeModuli) {
            Config config = scannerConfig.createConfig();
            config.setDefaultServerSupportedCipherSuites(supportedDheCipherSuites);
            config.setDefaultServerEphemeralDhModulus(modulus.getModulus());
            if (testConfig(config)) {
                return modulus.getBitLength();
            }
        }
        return null;
    }

    private boolean testConfig(Config config) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
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
                    config.setDefaultServerEphemeralDhModulus(
                            createEvenModulus(lowestDheModulusLength));
                    break;
                case MOD3:
                    config.setDefaultServerEphemeralDhModulus(
                            createModThreeModulus(lowestDheModulusLength));
                    break;
                default:
                    break;
            }
            if (testConfig(config)) {
                compositeModulusResultList.add(
                        new CompositeModulusResult(TestResults.TRUE, compositeType));
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
        // we xor here to ensure the modulus will be even (was odd), but keeps the same
        // bit length
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
                    config.setDefaultServerEphemeralDhGenerator(BigInteger.ONE);
                    break;
                case MODULUS_ONE:
                    config.setDefaultServerEphemeralDhModulus(BigInteger.ONE);
                    break;
                default:
                    break;
            }
            if (testConfig(config)) {
                smallSubgroupResultList.add(
                        new SmallSubgroupResult(TestResults.TRUE, smallSubgroupType));
            } else {
                smallSubgroupResultList.add(
                        new SmallSubgroupResult(TestResults.FALSE, smallSubgroupType));
            }
        }
        return smallSubgroupResultList;
    }

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.LOWEST_POSSIBLE_DHE_MODULUS_SIZE, lowestDheModulusLength);
        put(TlsAnalyzedProperty.HIGHEST_POSSIBLE_DHE_MODULUS_SIZE, highestDheModulusLength);
        mergeCompositeModulusResult(report);
        mergeSmallSubgroupResult(report);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProbeRequirement<ClientReport>(TlsProbeType.CIPHER_SUITE)
                .and(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_DHE));
    }

    @Override
    public void adjustConfig(ClientReport report) {
        supportedDheCipherSuites = new LinkedList<>();
        for (CipherSuite suite : report.getSupportedCipherSuites()) {
            if (AlgorithmResolver.getKeyExchangeAlgorithm(suite) != null
                    && AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeDhe()) {
                supportedDheCipherSuites.add(suite);
            }
        }
    }

    private HashMap<CompositeModulusType, TlsAnalyzedProperty> getCompositeModulusTypeMap() {
        HashMap<CompositeModulusType, TlsAnalyzedProperty> compositeModulusTypeMap =
                new HashMap<>();
        compositeModulusTypeMap.put(
                CompositeModulusType.EVEN, TlsAnalyzedProperty.SUPPORTS_EVEN_MODULUS);
        compositeModulusTypeMap.put(
                CompositeModulusType.MOD3, TlsAnalyzedProperty.SUPPORTS_MOD3_MODULUS);
        return compositeModulusTypeMap;
    }

    private HashMap<SmallSubgroupType, TlsAnalyzedProperty> getSmallSubgroupTypeMap() {
        HashMap<SmallSubgroupType, TlsAnalyzedProperty> smallSubgroupTypeMap = new HashMap<>();
        smallSubgroupTypeMap.put(
                SmallSubgroupType.MODULUS_ONE, TlsAnalyzedProperty.SUPPORTS_MODULUS_ONE);
        smallSubgroupTypeMap.put(
                SmallSubgroupType.MODULUS_ZERO, TlsAnalyzedProperty.SUPPORTS_MODULUS_ZERO);
        smallSubgroupTypeMap.put(
                SmallSubgroupType.GENERATOR_ONE, TlsAnalyzedProperty.SUPPORTS_GENERATOR_ONE);
        smallSubgroupTypeMap.put(
                SmallSubgroupType.GENERATOR_ZERO, TlsAnalyzedProperty.SUPPORTS_GENERATOR_ZERO);
        return smallSubgroupTypeMap;
    }

    private void mergeCompositeModulusResult(ClientReport report) {
        if (compositeModulusResultList == null) {
            for (TlsAnalyzedProperty property : compositeModulusTypeToPropertyMapping.values()) {
                put(property, TestResults.COULD_NOT_TEST);
            }
            return;
        }
        for (CompositeModulusResult compositeResult : compositeModulusResultList) {
            TlsAnalyzedProperty property =
                    compositeModulusTypeToPropertyMapping.get(compositeResult.getType());
            put(property, compositeResult.getResult());
        }
    }

    private void mergeSmallSubgroupResult(ClientReport report) {
        if (smallSubgroupResults == null) {
            for (TlsAnalyzedProperty property : smallSubgroupTypeToPropertyMapping.values()) {
                put(property, TestResults.COULD_NOT_TEST);
            }
            return;
        }
        for (SmallSubgroupResult smallSubgroupResult : smallSubgroupResults) {
            TlsAnalyzedProperty property =
                    smallSubgroupTypeToPropertyMapping.get(smallSubgroupResult.getType());
            put(property, smallSubgroupResult.getResult());
        }
    }
}
