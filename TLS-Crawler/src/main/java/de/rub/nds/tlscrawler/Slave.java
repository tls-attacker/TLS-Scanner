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
import de.rub.nds.tlscrawler.core.TlsCrawlerSlave;
import de.rub.nds.tlscrawler.options.SlaveOptions;
import de.rub.nds.tlscrawler.options.StartupOptions;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.orchestration.InMemoryOrchestrationProvider;
import de.rub.nds.tlscrawler.orchestration.RedisOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.persistence.InMemoryPersistenceProvider;
import de.rub.nds.tlscrawler.persistence.MongoPersistenceProvider;
import de.rub.nds.tlscrawler.scans.IScan;
import de.rub.nds.tlscrawler.scans.ScanFactory;
import de.rub.nds.tlscrawler.utility.Tuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ConnectException;
import java.util.Collection;

/**
 * Slave instance main class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class Slave {
    private static Logger LOG = LoggerFactory.getLogger(Slave.class);

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
            System.out.println(SlaveOptions.getHelpString());
            System.exit(0);
        }

        Collection<IScan> scans = ScanFactory.getInstance().getBuiltInScans();
        Tuple<IOrchestrationProvider, IPersistenceProvider> providers = setUpProviders(options, "defaultScan");

        ITlsCrawlerSlave slave = new TlsCrawlerSlave(
                options.instanceId,
                providers.getFirst(),
                providers.getSecond(),
                scans,
                options.numberOfThreads);

        slave.start();

        LOG.info("TLS-Crawler is running as a slave node with id " + options.instanceId + ".");

        new Thread(() -> {
            for (;;) {
                LOG.info(slave.getStats().toString());
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    // die!
                }
            }
        }).start();
    }

    
    static Tuple<IOrchestrationProvider, IPersistenceProvider> setUpProviders(StartupOptions options, String scanName) {
        LOG.trace("setUpProviders()");

        if (options == null) {
            throw new IllegalArgumentException("'options' must not be null.");
        }

        IOrchestrationProvider orchestrationProvider;
        IPersistenceProvider persistenceProvider;

        String workspace = options.workspace;
        String workspaceWithPrefix = String.format("TLSC-dev-%s", workspace);

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
            mpp.init(workspaceWithPrefix, scanName);

            persistenceProvider = mpp;

            if (!options.inMemoryOrchestration) {
                RedisOrchestrationProvider rop = new RedisOrchestrationProvider(
                        options.redisHost,
                        options.redisPort,
                        options.redisPass);

                try {
                    rop.init(workspaceWithPrefix);
                } catch (ConnectException e) {
                    LOG.error("Could not connect to redis.", e);
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
}
