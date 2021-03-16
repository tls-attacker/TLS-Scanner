/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.config.modes;

import java.io.File;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsscanner.clientscanner.ClientScanExecutor;
import de.rub.nds.tlsscanner.clientscanner.Main;
import de.rub.nds.tlsscanner.clientscanner.client.DefaultOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.ClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.config.BaseSubcommandHolder;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.config.ExecutableSubcommand;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.ClientAdapterConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.DockerLibAdapterConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.BaseCommandAdapterConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;

@Parameters(commandNames = "scanClient", commandDescription = "Scan a client automatically")
public class ScanClientCommandConfig extends BaseSubcommandHolder<ClientAdapterConfig> implements ExecutableSubcommand {
    @Parameter(names = "-file", required = false, description = "File to write the report to as xml")
    private String reportFile = null;

    @Parameter(names = { "-primaryThreads", "-pT" }, required = false, description = "Primary threads")
    protected Integer primaryThreads = null;

    @Parameter(names = { "-secondaryThreads",
            "-sT" }, required = false, description = "Secondary threads - these may be used by Probes to run more tasks")
    protected Integer secondaryThreads = null;

    public ScanClientCommandConfig() {
        subcommands.add(new DockerLibAdapterConfig());
        subcommands.addAll(BaseCommandAdapterConfig.getAll());
    }

    @Override
    protected void applyDelegateInternal(Config config) {
        // use any port
        InboundConnection inboundConnection = config.getDefaultServerConnection();
        if (inboundConnection == null) {
            config.setDefaultServerConnection(new InboundConnection(0));
        } else {
            inboundConnection.setPort(0);
        }
    }

    public ClientAdapter createClientAdapter(ClientScannerConfig csConfig) {
        return selectedSubcommand.createClientAdapter(csConfig);
    }

    @Override
    public void execute(ClientScannerConfig csConfig) {
        if (primaryThreads == null) {
            primaryThreads = Runtime.getRuntime().availableProcessors();
        }
        if (secondaryThreads == null) {
            secondaryThreads = primaryThreads;
        }
        ThreadPoolExecutor pool = new ThreadPoolExecutor(primaryThreads, primaryThreads, 1, TimeUnit.MINUTES,
                new LinkedBlockingDeque<>(),
                new NamedThreadFactory("cs-probe-runner"));
        // can't decrease core size without additional hassle
        // https://stackoverflow.com/a/15485841/3578387
        ThreadPoolExecutor secondaryPool = new ThreadPoolExecutor(secondaryThreads, secondaryThreads, 1,
                TimeUnit.MINUTES,
                new LinkedBlockingDeque<>(),
                new NamedThreadFactory("cs-secondary-pool"));
        // Orchestrator types: DefaultOrchestrator and ThreadLocalOrchestrator
        Orchestrator orchestrator = new DefaultOrchestrator(csConfig, secondaryPool, primaryThreads + secondaryThreads);

        ClientScanExecutor executor = new ClientScanExecutor(Main.getDefaultProbes(orchestrator), null, orchestrator,
                pool);
        ClientReport rep;
        try {
            rep = executor.execute();
        } finally {
            secondaryPool.shutdown();
            pool.shutdown();
        }

        try {
            File file = null;
            if (reportFile != null) {
                file = new File(reportFile);
            }
            JAXBContext ctx;
            ctx = JAXBContext.newInstance(ClientReport.class);
            Marshaller marsh = ctx.createMarshaller();
            marsh.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marsh.marshal(rep, System.out);
            if (file != null) {
                marsh.marshal(rep, file);
            }
        } catch (JAXBException e) {
            // Nothing we can do about failing to serialize the report :/
            e.printStackTrace();
        }
    }

}
