/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import java.net.ConnectException;
import java.util.ArrayList;
import java.util.Collection;

/**
 * An orchestration provider implementation using Redis as an external source.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class RedisOrchestrationProvider implements IOrchestrationProvider {

    private static Logger LOG = LoggerFactory.getLogger(RedisOrchestrationProvider.class);

    private static int REDIS_TIMEOUT = 30000; // in ms

    private boolean initialized = false;

    private String redisHost;
    private int redisPort;
    private String redisPass;

    private JedisPool jedisPool;

    private String taskListName = null;

    public RedisOrchestrationProvider(String redisHost, int redisPort, String redisPass) {
        this.redisHost = redisHost;
        this.redisPort = redisPort;
        this.redisPass = redisPass;
    }

    public void init(String taskListName) throws ConnectException {
        LOG.trace("init() - Enter");

        JedisPoolConfig cfg = new JedisPoolConfig();
        cfg.setMaxIdle(GenericObjectPoolConfig.DEFAULT_MAX_IDLE);
        cfg.setMinIdle(GenericObjectPoolConfig.DEFAULT_MIN_IDLE);
        cfg.setTestOnBorrow(true);

        if (!this.redisPass.equals("")) {
            this.jedisPool = new JedisPool(cfg, this.redisHost, this.redisPort, REDIS_TIMEOUT, this.redisPass);
        } else {
            this.jedisPool = new JedisPool(cfg, this.redisHost, this.redisPort, REDIS_TIMEOUT);
        }

        try (Jedis jedis = this.jedisPool.getResource()) {
            if (jedis.isConnected()) {
                LOG.info("Connected to Redis at " + this.redisHost + ":" + this.redisPort);
            } else {
                LOG.error("Connecting to Redis failed.");
                throw new ConnectException("Could not connect to Redis endpoint.");
            }
        }
        LOG.info("Redis Tasks are listed in:" + taskListName);
        this.taskListName = taskListName;

        this.initialized = true;
        LOG.trace("init() - Leave");
    }

    /**
     * Convenience method to block method entry in situations where the
     * orchestration provider is not initialized.
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
        this.checkInit();

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
    public void addScanTask(String taskId) {
        this.checkInit();

        LOG.trace("addScanTask()");

        try (Jedis jedis = this.jedisPool.getResource()) {
            jedis.lpush(this.taskListName, taskId);
        }
    }

    @Override
    public void addScanTasks(Collection<String> taskIds) {
        this.checkInit();

        LOG.trace("addScanTasks()");

        String[] tids = taskIds.toArray(new String[taskIds.size()]);

        try (Jedis jedis = this.jedisPool.getResource()) {
            jedis.lpush(this.taskListName, tids);
        }
    }
}
