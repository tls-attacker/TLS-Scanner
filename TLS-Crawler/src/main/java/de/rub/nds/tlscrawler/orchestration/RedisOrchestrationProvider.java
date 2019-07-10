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
import redis.clients.jedis.JedisPool;

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

    private boolean initialized = false;
    private String redisConnectionString;
    private JedisPool jedisPool;

    private String taskListName = "myList";

    public RedisOrchestrationProvider(String redisConnString) {
        this.redisConnectionString = redisConnString;
    }

    public void init(String taskListName) throws ConnectException {
        LOG.trace("init() - Enter");
        this.jedisPool = new JedisPool(this.redisConnectionString);

        try (Jedis jedis = this.jedisPool.getResource()) {
            if (jedis.isConnected()) {
                LOG.info("Connected to Redis at " +
                        (this.redisConnectionString.equals("") ? "localhost" : this.redisConnectionString));
            } else {
                LOG.error("Connecting to Redis failed.");
                throw new ConnectException("Could not connect to Redis endpoint.");
            }
        }

        this.taskListName = taskListName;

        this.initialized = true;
        LOG.trace("init() - Leave");
    }

    /**
     * Convenience method to block method entry in situations where the orchestration provider is not initialized.
     */
    private void checkInit() {
        if (!this.initialized) {
            String error = String.format("%s has not been initialized.",
                    RedisOrchestrationProvider.class.getName());

            LOG.error(error);
            throw new RuntimeException(error);
        }
    }

    @Override
    public String getScanTask() {
        this.checkInit();

        LOG.trace("getScanTask()");

        String result;
        try (Jedis jedis = this.jedisPool.getResource()) {
            result = jedis.rpop(this.taskListName);
        }

        return result;
    }

    @Override
    public long getNumberOfTasks() {
        long listLength;
        try (Jedis redis = this.jedisPool.getResource()) {
            listLength = redis.llen(this.taskListName);
        }
        return listLength;
    }

    @Override
    public Collection<String> getScanTasks(int quantity) {
        this.checkInit();

        LOG.trace("getScanTasks() - Enter");

        Collection<String> result = new ArrayList<>(quantity);
        try (Jedis jedis = this.jedisPool.getResource()) {
            for (int i = 0; i < quantity; i++) {
                // TODO: Bulk operation possible?
                String scanTaskId = jedis.rpop(this.taskListName);

                if (scanTaskId != null) {
                    result.add(scanTaskId);
                } else {
                    break;
                }
            }
        }

        LOG.trace("getScanTasks() - Leave");

        return result;
    }

    @Override
    public void addScanTask(String task) {
        this.checkInit();

        LOG.trace("addScanTask()");

        try (Jedis jedis = this.jedisPool.getResource()) {
            jedis.lpush(this.taskListName, task);
        }
    }
}
