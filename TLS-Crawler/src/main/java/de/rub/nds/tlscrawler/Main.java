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
import com.mongodb.MongoClient;
import com.mongodb.MongoTimeoutException;
import de.rub.nds.tlscrawler.data.IScan;
import de.rub.nds.tlscrawler.scans.PingScan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

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
        CLOptions options = null;

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

        // TODO: Set up scans. TBD: Scan plug-ins.
        List<IScan> scans = new LinkedList<>();
        scans.add(new PingScan());


        MongoClient mongo = new MongoClient(options.mongoDbConnectionString);
        try {
            String address = mongo.getAddress().toString();
            LOG.info("Connected to MongoDB at " + address);
        } catch (MongoTimeoutException ex) {
            LOG.error("Connecting to MongoDB failed.");
            System.exit(0);
        }

        String redisEndpoint = options.redisConnectionString;
        Jedis jedis = new Jedis(redisEndpoint);
        jedis.connect();
        if (jedis.isConnected()) {
            LOG.info("Connected to Redis at " + (redisEndpoint.equals("") ? "localhost" : redisEndpoint));
        } else {
            LOG.error("Connecting to Redis failed.");
            System.exit(0);
        }

        // Set up crawler

        LOG.info("TLS-Crawler is running as a " + (options.isMaster ? "master" : "slave") + " node with id "
                + options.instanceId + ".");
    }

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
            result = null;
        }

        if (result != null && result.testMode && !result.isMaster) {
            result = null;
        }

        if (result != null && result.testMode && !result.inMemoryOrchestration) {
            result = null;
        }

        return result;
    }
}
