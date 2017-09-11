/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import de.rub.nds.tlscrawler.data.IScanTask;
import redis.clients.jedis.Jedis;

/**
 * An orchestration provider implementation using Redis
 * as an external source.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class RedisOrchestrationProvider implements IOrchestrationProvider {
    private Jedis redis;

    public RedisOrchestrationProvider(Jedis redis) {
        this.redis = redis;
    }

    public IScanTask getScanTask() {
        // retrieve scan task from redis
        return null;
    }

    public void addScanTask(IScanTask task) {
        // write scan task to redis
    }
}
