/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import com.google.devtools.common.options.OptionsParser;
import com.google.devtools.common.options.OptionsParsingException;
import com.mongodb.MongoClientURI;
import de.rub.nds.tlscrawler.core.ITlsCrawlerSlave;
import de.rub.nds.tlscrawler.core.TlsCrawlerMaster;
import de.rub.nds.tlscrawler.core.TlsCrawlerSlave;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.orchestration.InMemoryOrchestrationProvider;
import de.rub.nds.tlscrawler.orchestration.RedisOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.persistence.InMemoryPersistenceProvider;
import de.rub.nds.tlscrawler.persistence.MongoPersistenceProvider;
import de.rub.nds.tlscrawler.scans.IScan;
import de.rub.nds.tlscrawler.scans.NullScan;
import de.rub.nds.tlscrawler.scans.PingScan;
import de.rub.nds.tlscrawler.scans.TestScan;
import de.rub.nds.tlscrawler.utility.Tuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ConnectException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

/**
 * TLS-Crawler's main class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class Main {
    private static Logger LOG = LoggerFactory.getLogger(Main.class);

    private static String usageInfo;

    public static void main(String[] args) {
        CLOptions options;

        try {
            options = parseOptions(args);
        } catch (OptionsParsingException ex) {
            LOG.error("Command Line Options could not be parsed.");
            options = null;
        }

        if (options == null || options.help) {
            System.out.println("Could not parse Command Line Options. Try again:");
            System.out.println(usageInfo);
            System.exit(0);
        }

        List<IScan> scans = setUpScans();

        Tuple<IOrchestrationProvider, IPersistenceProvider> providers = setUpProviders(options);

        ITlsCrawlerSlave slave = new TlsCrawlerSlave(providers.getFirst(), providers.getSecond(), scans);
        slave.start();

        TlsCrawlerMaster master = new TlsCrawlerMaster(providers.getFirst(), providers.getSecond(), scans);

        LOG.info("TLS-Crawler is running as a " + (options.isMaster ? "master" : "slave") + " node with id "
                + options.instanceId + ".");

        CommandLineInterface.handleInput(master, slave);
    }

    private static Tuple<IOrchestrationProvider, IPersistenceProvider> setUpProviders(CLOptions options) {
        if (options == null) {
            throw new IllegalArgumentException("'options' must not be null.");
        }

        IOrchestrationProvider orchestrationProvider;
        IPersistenceProvider persistenceProvider;

        if (!options.testMode) {
            MongoPersistenceProvider mpp = new MongoPersistenceProvider(new MongoClientURI(options.mongoDbConnectionString));
            mpp.init("myDb");

            persistenceProvider = mpp;

            if (!options.inMemoryOrchestration) {
                RedisOrchestrationProvider rop = new RedisOrchestrationProvider(options.redisConnectionString);

                try {
                    rop.init("myList");
                } catch (ConnectException e) {
                    LOG.error("Could not connect to redis.");
                    System.exit(0);
                }

                orchestrationProvider = rop;
            } else { // in-memory-orchestration:
                orchestrationProvider = new InMemoryOrchestrationProvider();
            }
        } else { // TLS Crawler is in test mode:
            orchestrationProvider = new InMemoryOrchestrationProvider();
            persistenceProvider = new InMemoryPersistenceProvider();
        }

        return Tuple.create(orchestrationProvider, persistenceProvider);
    }

    // TODO: Maybe move to CLOptions class.
    /**
     * Implements command line argument parsing.
     *
     * @param args The argument array.
     * @return An object containing sane arguments.
     * @throws OptionsParsingException
     */
    static CLOptions parseOptions(String[] args) throws OptionsParsingException {
        CLOptions result;

        OptionsParser parser = OptionsParser.newOptionsParser(CLOptions.class);
        usageInfo = parser.describeOptions(Collections.<String, String>emptyMap(), OptionsParser.HelpVerbosity.LONG);

        parser.parse(args);
        result = parser.getOptions(CLOptions.class);

        if (result != null && result.instanceId.equals("")) {
            result.instanceId = UUID.randomUUID().toString();
        }

        if (result != null && result.masterOnly && !result.isMaster) {
            LOG.warn("Overridden 'isMaster' to true due to 'masterOnly'.");
            result.isMaster = true;
        }

        if (result != null && result.testMode && !result.isMaster) {
            LOG.warn("Overridden 'isMaster' to true due to 'testMode' option.");
            result.isMaster = true;
        }

        if (result != null && result.testMode && !result.inMemoryOrchestration) {
            LOG.warn("Overridden 'inMemoryOrchestration' to true due to 'testMode' option.");
            result.inMemoryOrchestration = true;
        }

        return result;
    }

    /**
     * Set up for known scans // TODO and plugin-provided scans.
     *
     * @return A list of scans.
     */
    private static List<IScan> setUpScans() {
        List<IScan> result = new LinkedList<>();

        // Set up known scans.
        result.add(new PingScan());
        result.add(new TestScan());
        result.add(new NullScan());

        // TODO: Set up plugins

        return result;
    }
}
