/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketBaseProbe;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionTicketCollectingProbe extends SessionTicketBaseProbe {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final int TICKETS_TO_GATHER = 10;

    public SessionTicketCollectingProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, configSelector, TlsProbeType.SESSION_TICKET_COLLECTOR);
    }

    @Override
    public void executeTest() {
        for (ProtocolVersion version : versionsToTest) {
            try {
                collectTickets(version);

            } catch (Exception E) {
                LOGGER.warn("Could not collect SessionTickets for version {}", version, E);
                if (E.getCause() instanceof InterruptedException) {
                    LOGGER.error("Timeout on {}", getProbeName());
                    throw E;
                }
            }
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        // Nothing to do here - all data analysis is done in the after probe
    }

    private void collectTickets(ProtocolVersion version) {
        if (!issuesTickets(version)) {
            return;
        }

        List<State> statesToExecute = new LinkedList<>();
        for (int i = 0; i < TICKETS_TO_GATHER; i++) {
            statesToExecute.add(prepareInitialHandshake(version));
        }
        executeState(statesToExecute);
    }
}
