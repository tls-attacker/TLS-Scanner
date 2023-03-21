/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
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
import de.rub.nds.tlsscanner.clientscanner.probe.result.DheParameterResult;
import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.CompositeModulusResult;
import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.SmallSubgroupResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
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
        random = new Random(0);
        primeModuli = Arrays.asList(PrimeModulus.values());
    }

    @Override
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
                    config.setDefaultServerDhModulus(createEvenModulus(lowestDheModulusLength));
                    break;
                case MOD3:
                    config.setDefaultServerDhModulus(createModThreeModulus(lowestDheModulusLength));
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
}
