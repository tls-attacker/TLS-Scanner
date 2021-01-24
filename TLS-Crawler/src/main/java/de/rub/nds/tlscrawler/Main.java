/**
 * TLS Crawler
 * <p>
 * Licensed under Apache 2.0
 * <p>
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import com.beust.jcommander.JCommander;
import com.mongodb.ConnectionString;
import com.mongodb.MongoCredential;
import de.rub.nds.tlscrawler.config.AnalysisCommandConfig;
import de.rub.nds.tlscrawler.config.ControllerCommandConfig;
import de.rub.nds.tlscrawler.config.WorkerCommandConfig;
import de.rub.nds.tlscrawler.config.delegate.MongoDbDelegate;
import de.rub.nds.tlscrawler.config.delegate.RedisDelegate;
import de.rub.nds.tlscrawler.core.Controller;
import de.rub.nds.tlscrawler.core.ITlsCrawlerWorker;
import de.rub.nds.tlscrawler.core.TlsCrawlerWorker;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.orchestration.RedisOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.persistence.MongoPersistenceProvider;
import java.net.ConnectException;
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

    public static void main(String[] args) throws ConnectException {

        Logger mongoLogger = Logger.getLogger("org.mongodb.driver");
        mongoLogger.setLevel(Level.SEVERE);
        mongoLogger = Logger.getLogger("org.mongodb.driver.cluster");
        mongoLogger.setLevel(Level.SEVERE);

        JCommander jc = new JCommander();
        ControllerCommandConfig controllerCommandConfig = new ControllerCommandConfig();
        jc.addCommand("controller", controllerCommandConfig);

        WorkerCommandConfig workerCommandConfig = new WorkerCommandConfig();
        jc.addCommand("worker", workerCommandConfig);

        AnalysisCommandConfig analysisCommandConfig = new AnalysisCommandConfig();
        jc.addCommand("analysis", analysisCommandConfig);

        jc.parse(args);
        if (jc.getParsedCommand() == null) {
            jc.usage();
        }

        switch (jc.getParsedCommand().toLowerCase()) {
            case "worker":
                ITlsCrawlerWorker worker = new TlsCrawlerWorker(workerCommandConfig.getInstanceId(), setUpOrchestrationProvider(workerCommandConfig.getRedisDelegate()), setUpPersistenceProvider(workerCommandConfig.getMongoDbDelegate()), workerCommandConfig.getNumberOfThreads());
                worker.start();
                break;
            case "controller":
                Controller controller = new Controller(controllerCommandConfig, setUpOrchestrationProvider(controllerCommandConfig.getRedisDelegate()));
                controller.start();
                break;
            default:
                jc.usage();
        }
    }

    static IPersistenceProvider setUpPersistenceProvider(MongoDbDelegate delegate) {
        ConnectionString connectionString = new ConnectionString("mongodb://" + delegate.getMongoDbHost() + ":" + delegate.getMongoDbPort());
        MongoCredential credential = null;

        credential = MongoCredential.createCredential(
            delegate.getMongoDbUser(),
            delegate.getMongoDbAuthSource(),
            delegate.getMongoDbPass().toCharArray());

        return new MongoPersistenceProvider(connectionString, credential);
    }

    static IOrchestrationProvider setUpOrchestrationProvider(RedisDelegate delegate) throws ConnectException {
        RedisOrchestrationProvider redisOrchestrationProvider = new RedisOrchestrationProvider(
            delegate.getRedisHost(),
            delegate.getRedisPort(),
            delegate.getRedisPass());

        redisOrchestrationProvider.init("TLSC-blacklist", delegate.getJobQueue());

        return redisOrchestrationProvider;
    }
}
