/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import com.google.devtools.common.options.OptionsParsingException;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import de.rub.nds.tlscrawler.core.ITlsCrawlerSlave;
import de.rub.nds.tlscrawler.core.TlsCrawlerMaster;
import de.rub.nds.tlscrawler.core.TlsCrawlerSlave;
import de.rub.nds.tlscrawler.options.StartupOptions;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.orchestration.InMemoryOrchestrationProvider;
import de.rub.nds.tlscrawler.orchestration.RedisOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.persistence.InMemoryPersistenceProvider;
import de.rub.nds.tlscrawler.persistence.MongoPersistenceProvider;
import de.rub.nds.tlscrawler.scans.*;
import de.rub.nds.tlscrawler.utility.Tuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ConnectException;
import java.util.LinkedList;
import java.util.List;

/**
 * TLS-Crawler's main class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class Main {
    private static Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        StartupOptions options;

        try {
            options = StartupOptions.parseOptions(args);
        } catch (OptionsParsingException ex) {
            LOG.error("Command Line Options could not be parsed.");
            options = null;
        }

        if (options == null || options.help) {
            System.out.println("Could not parse Command Line Options. Try again:");
            System.out.println(StartupOptions.getHelpString());
            System.exit(0);
        }

        List<IScan> scans = setUpScans();

        Tuple<IOrchestrationProvider, IPersistenceProvider> providers = setUpProviders(options);

        ITlsCrawlerSlave slave = new TlsCrawlerSlave(options.instanceId, providers.getFirst(), providers.getSecond(), scans);
        slave.start();

        TlsCrawlerMaster master = new TlsCrawlerMaster(options.instanceId, providers.getFirst(), providers.getSecond(), scans);

        LOG.info("TLS-Crawler is running as a " + (options.isMaster ? "master" : "slave") + " node with id "
                + options.instanceId + ".");

        CommandLineInterface.handleInput(master, slave);
    }

    static Tuple<IOrchestrationProvider, IPersistenceProvider> setUpProviders(StartupOptions options) {
        LOG.trace("setUpProviders()");

        if (options == null) {
            throw new IllegalArgumentException("'options' must not be null.");
        }

        IOrchestrationProvider orchestrationProvider;
        IPersistenceProvider persistenceProvider;

        String workspace = options.workspace;
        String workspaceWithPrefix = String.format("TLSC-%s", workspace);

        if (!options.testMode) {
            ServerAddress address = new ServerAddress(options.mongoDbHost, options.mongoDbPort);
            MongoCredential credential = null;

            if (!options.mongoDbUser.equals("")) {
                credential = MongoCredential.createCredential(
                        options.mongoDbUser,
                        options.mongoDbAuthSource,
                        options.mongoDbPass.toCharArray());
            }

            MongoPersistenceProvider mpp = new MongoPersistenceProvider(address, credential);
            mpp.init(workspaceWithPrefix);

            persistenceProvider = mpp;

            if (!options.inMemoryOrchestration) {
                RedisOrchestrationProvider rop = new RedisOrchestrationProvider(
                        options.redisHost,
                        options.redisPort,
                        options.redisPass);

                try {
                    rop.init(workspaceWithPrefix);
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

    /**
     * Set up for known scans.
     *
     * @return A list of scans.
     */
    static List<IScan> setUpScans() {
        LOG.trace("setUpScans()");

        List<IScan> result = new LinkedList<>(ScanFactory.getInstance().getBuiltInScans());

        return result;
    }
}
