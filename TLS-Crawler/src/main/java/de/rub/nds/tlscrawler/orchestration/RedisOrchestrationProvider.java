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

import java.net.ConnectException;
import java.util.ArrayList;
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

    private String taskListName = "myList";

    public RedisOrchestrationProvider(String redisConnString) {
        this.redisConnectionString = redisConnString;
    }

    public void init() throws ConnectException {
        this.redis = new Jedis(this.redisConnectionString);

        this.redis.connect();
        if (this.redis.isConnected()) {
            LOG.info("Connected to Redis at " +
                    (this.redisConnectionString.equals("") ? "localhost" : this.redisConnectionString));
        } else {
            LOG.error("Connecting to Redis failed.");
            throw new ConnectException("Could not connect to redis endpoint.");
        }
    }

    @Override
    public String getScanTask() {
        return this.redis.rpop(this.taskListName);
    }

    @Override
    public Collection<String> getScanTasks(int quantity) {
        Collection<String> result = new ArrayList<>(quantity);

        for (int i = 0; i < quantity; i++) {
            // TODO: Bulk operation possible?
            String scanTaskId = this.getScanTask();

            if (scanTaskId != null) {
                result.add(scanTaskId);
            } else {
                break;
            }
        }

        return result;
    }

    @Override
    public void addScanTask(String task) {
        this.redis.lpush(this.taskListName, task);
    }
}
