/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import de.rub.nds.tlsscanner.serverscanner.test.AbstractDockerbasedIT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractProbeIT extends AbstractDockerbasedIT {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int MAX_ATTEMPTS = 3;

    protected ServerReport report;
    protected ParallelExecutor parallelExecutor;
    protected ConfigSelector configSelector;

    public AbstractProbeIT(
            TlsImplementationType implementation, String version, String additionalParameters) {
        super(implementation, version, additionalParameters);
    }

    public AbstractProbeIT(
            TlsImplementationType implementation,
            String version,
            String additionalParameters,
            TransportType transportType) {
        super(implementation, version, additionalParameters, transportType);
    }

    @Test
    public void testProbe() throws InterruptedException {
        LOGGER.info("Testing: " + getProbe().getProbeName());
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            try {
                executeProbe();
                if (executedAsPlanned()) {
                    return;
                }
            } catch (Exception ignored) {
                LOGGER.error(
                        "Encountered exception during scanner execution ({})",
                        ignored.getMessage(),
                        ignored);
            }
            LOGGER.warn("Failed to complete scan, reexecuting...");
            killContainer();
            prepareContainer();
        }
        LOGGER.error("Failed {}", getProbe().getProbeName());
        Assertions.fail();
    }

    private void executeProbe() {
        // Preparing config, executor, config selector, and report
        ServerScannerConfig config = new ServerScannerConfig(new GeneralDelegate());
        config.getClientDelegate().setHost(getServerAddress());
        parallelExecutor = ParallelExecutor.create(1, 3);
        configSelector = new ConfigSelector(config, parallelExecutor);
        configSelector.findWorkingConfigs();
        report = new ServerReport();
        prepareReport();
        // Executing probe
        TlsServerProbe probe = getProbe();
        probe.adjustConfig(report);
        probe.call();
        probe.merge(report);
    }

    @AfterEach
    public void tearDownParallelExecutor() {
        if (parallelExecutor != null) {
            parallelExecutor.shutdown();
        }
    }

    protected abstract TlsServerProbe getProbe();

    protected abstract void prepareReport();

    protected abstract boolean executedAsPlanned();

    protected boolean verifyProperty(TlsAnalyzedProperty property, TestResult result) {
        return report.getResult(property) == result;
    }
}
