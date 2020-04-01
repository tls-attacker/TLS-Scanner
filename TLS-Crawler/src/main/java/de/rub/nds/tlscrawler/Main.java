/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import com.google.devtools.common.options.OptionsParsingException;
import static de.rub.nds.tlscrawler.Slave.setUpProviders;
import de.rub.nds.tlscrawler.core.ITlsCrawlerSlave;
import de.rub.nds.tlscrawler.core.TlsCrawlerSlave;
import de.rub.nds.tlscrawler.options.StartupOptions;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.scans.*;
import de.rub.nds.tlscrawler.utility.Tuple;

import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.logging.log4j.LogManager;

/**
 * TLS-Crawler's main class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class Main {

    private static final org.apache.logging.log4j.Logger LOG = LogManager.getLogger();

    public static void main(String[] args) {

        Logger mongoLogger = Logger.getLogger("org.mongodb.driver");
        mongoLogger.setLevel(Level.SEVERE);
        mongoLogger = Logger.getLogger("org.mongodb.driver.cluster");
        mongoLogger.setLevel(Level.SEVERE);
        StartupOptions options;

        try {
            options = StartupOptions.parseOptions(args);
        } catch (OptionsParsingException ex) {
            LOG.error("Command Line Options could not be parsed.", ex);
            options = null;
        }

        if (options == null || options.help) {
            System.out.println("Could not parse Command Line Options. Try again:");
            System.out.println(StartupOptions.getHelpString());
            System.exit(0);
        }

        List<IScan> scans = setUpScans();

        Tuple<IOrchestrationProvider, IPersistenceProvider> providers = setUpProviders(options, "defaultScan");

        ITlsCrawlerSlave slave = new TlsCrawlerSlave(options.instanceId, providers.getFirst(), providers.getSecond(), scans, options.port);
        slave.start();
    }

    /**
     * Set up for known scans.
     *
     * @return A list of scans.
     */
    static List<IScan> setUpScans() {
        LOG.trace("setUpScans()");

        List<IScan> result = new LinkedList<>();
        result.add(new TlsScan());
        return result;
    }
}
