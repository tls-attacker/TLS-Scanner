/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.drown;

import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.constans.DrownVulnerabilityType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class BaseDrownAttacker {

    private static final Logger LOGGER = LogManager.getLogger();

    protected Config tlsConfig;
    protected ParallelExecutor executor;

    public BaseDrownAttacker(Config baseConfig, ParallelExecutor executor) {
        this.tlsConfig = baseConfig;
        this.executor = executor;
    }

    public TestResults isVulnerable() {
        DrownVulnerabilityType type = getDrownVulnerabilityType();
        switch (type) {
            case GENERAL:
                LOGGER.debug("Server is vulnerable to the full General DROWN attack");
                return TestResults.TRUE;
            case SPECIAL:
                LOGGER.debug("Server is vulnerable to the full Special DROWN attack");
                return TestResults.TRUE;
            case SSL2:
                LOGGER.debug(
                        "Server supports SSL2, but not any weak cipher suites, so is not vulnerable to DROWN");
                return TestResults.FALSE;
            case NONE:
                return TestResults.FALSE;
            case UNKNOWN:
                LOGGER.debug(
                        "Could not execute Workflow, check previous messages or increase log level");
                return TestResults.ERROR_DURING_TEST;
            default:
                return TestResults.UNCERTAIN;
        }
    }

    public abstract DrownVulnerabilityType getDrownVulnerabilityType();
}
