/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import de.rub.nds.tlscrawler.config.MasterCommandConfig;
import com.beust.jcommander.JCommander;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import de.rub.nds.tlscrawler.analysis.DataAnalyser;
import de.rub.nds.tlscrawler.config.AnalysisCommandConfig;
import de.rub.nds.tlscrawler.config.SlaveCommandConfig;
import de.rub.nds.tlscrawler.core.ITlsCrawlerSlave;
import de.rub.nds.tlscrawler.core.TlsCrawlerSlave;
import de.rub.nds.tlscrawler.config.delegate.MongoDbDelegate;
import de.rub.nds.tlscrawler.config.delegate.RedisDelegate;
import de.rub.nds.tlscrawler.core.Master;
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
        MasterCommandConfig masterCommandConfig = new MasterCommandConfig();
        jc.addCommand("master", masterCommandConfig);

        SlaveCommandConfig slaveCommandConfig = new SlaveCommandConfig();
        jc.addCommand("slave", slaveCommandConfig);

        AnalysisCommandConfig analysisCommandConfig = new AnalysisCommandConfig();
        jc.addCommand("analysis", analysisCommandConfig);

        jc.parse(args);
        if (jc.getParsedCommand() == null) {
            if (jc.getParsedCommand() == null) {
                jc.usage();
            } else {
                jc.usage(jc.getParsedCommand());
            }
            return;
        }
        switch (jc.getParsedCommand().toLowerCase()) {
            case "slave":

                ITlsCrawlerSlave slave = new TlsCrawlerSlave(slaveCommandConfig.getInstanceId(), setUpOrchestrationProvider(slaveCommandConfig.getRedisDelegate()), setUpPersistenceProvider(slaveCommandConfig.getMongoDbDelegate()), slaveCommandConfig.getNumberOfThreads());
                slave.start();
                break;
            case "master":
                Master master = new Master(masterCommandConfig, setUpOrchestrationProvider(masterCommandConfig.getRedisDelegate()));
                master.start();
                break;
            case "analysis":
                DataAnalyser analyser = new DataAnalyser(analysisCommandConfig, setUpPersistenceProvider(analysisCommandConfig.getMongoDbDelegate()));
                analyser.analyze();
                break;
            default:
                jc.usage(jc.getParsedCommand());
        }
    }

    static IPersistenceProvider setUpPersistenceProvider(MongoDbDelegate delegate) {
        ServerAddress address = new ServerAddress(delegate.getMongoDbHost(), delegate.getMongoDbPort());
        MongoCredential credential = null;

        credential = MongoCredential.createCredential(
                delegate.getMongoDbUser(),
                delegate.getMongoDbAuthSource(),
                delegate.getMongoDbPass().toCharArray());

        return new MongoPersistenceProvider(address, credential);
    }

    static IOrchestrationProvider setUpOrchestrationProvider(RedisDelegate delegate) throws ConnectException {
        RedisOrchestrationProvider redisOrchestrationProvider = new RedisOrchestrationProvider(
                delegate.getRedisHost(),
                delegate.getRedisPort(),
                delegate.getRedisPass());

        redisOrchestrationProvider.init("TLSC-blacklist");

        return redisOrchestrationProvider;
    }
}
