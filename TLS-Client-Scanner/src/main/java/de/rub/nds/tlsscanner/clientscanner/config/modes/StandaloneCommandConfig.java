/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.config.modes;

import java.util.List;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsscanner.clientscanner.Main;
import de.rub.nds.tlsscanner.clientscanner.Server;
import de.rub.nds.tlsscanner.clientscanner.config.BaseSubcommandHolder;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.config.ExecutableSubcommand;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.Dispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIDispatcher;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.Probe;

@Parameters(commandNames = "standalone", commandDescription = "Host probes publicly")
public class StandaloneCommandConfig implements ExecutableSubcommand {
    private static final Logger LOGGER = LogManager.getLogger();

    @Parameter(names = { "-threads" }, required = false, description = "Primary threads")
    protected Integer threads = null;

    @Parameter(names = "-port", required = false, description = "Port to listen on")
    protected Integer port = 0;

    public StandaloneCommandConfig() {
        super();
    }

    @Override
    public void setParsed(JCommander jc) throws ParameterException {
        // nothing to do
    }

    @Override
    public void applyDelegate(Config config) {
        InboundConnection inboundConnection = config.getDefaultServerConnection();
        if (inboundConnection == null) {
            config.setDefaultServerConnection(new InboundConnection(port));
        } else {
            inboundConnection.setPort(port);
        }
    }

    private static Dispatcher getStandaloneDispatcher(ClientScannerConfig csConfig) {
        SNIDispatcher disp = new SNIDispatcher();
        LOGGER.info("Using base URL {}", csConfig.getServerBaseURL());
        disp.registerRule(csConfig.getServerBaseURL(), disp);
        List<Probe> probes = Main.getDefaultProbes(null);
        for (Probe p : probes) {
            if (p instanceof BaseProbe && p instanceof Dispatcher) {
                // TODO create some nice interface instead of expecting
                // BaseProbe
                // possibly also add some other form of configurability...
                String prefix = ((BaseProbe) p).getHostnameForStandalone();
                if (prefix != null) {
                    disp.registerRule(prefix, (Dispatcher) p);
                    LOGGER.info("Adding {} at prefix {}", p.getClass().getSimpleName(), prefix);
                } else {
                    LOGGER.debug("Not adding {} as it did not provide a hostname (returned null)", p.getClass()
                            .getSimpleName());
                }
            } else {
                LOGGER.debug("Not adding {} as it is not extended from BaseProbe", p.getClass().getSimpleName());
            }
        }
        return disp;
    }

    @Override
    public void execute(ClientScannerConfig csConfig) {
        if (threads == null) {
            threads = Runtime.getRuntime().availableProcessors();
        }
        Server s = new Server(csConfig, getStandaloneDispatcher(csConfig), threads);
        try {
            s.start();
            s.join();
        } catch (InterruptedException e) {
            LOGGER.error("Failed to wait for server exit due to interrupt", e);
            Thread.currentThread().interrupt();
        } finally {
            s.kill();
        }
    }

}
