/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

import java.util.Collection;

/**
 * An orchestration provider implementation using Redis
 * as an external source.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class RedisOrchestrationProvider implements IOrchestrationProvider {
    private static Logger LOG = LoggerFactory.getLogger(RedisOrchestrationProvider.class);

    private String redisConnectionString;
    private Jedis redis;

    public RedisOrchestrationProvider(String redisConnString) {
        this.redisConnectionString = redisConnString;
    }

    public void init() {
        this.redis = new Jedis(this.redisConnectionString);

        this.redis.connect();
        if (this.redis.isConnected()) {
            LOG.info("Connected to Redis at " +
                    (this.redisConnectionString.equals("") ? "localhost" : this.redisConnectionString));
        } else {
            LOG.error("Connecting to Redis failed.");
            System.exit(0);
        }
    }

    @Override
    public String getScanTask() {
        // TODO: retrieve scan task from redis
        return null;
    }

    @Override
    public Collection<String> getScanTasks(int quantity) {
        // TODO: retrieve qty scan tasks
        return null;
    }

    @Override
    public void addScanTask(String task) {
        // TODO: write scan task to redis
    }
}
