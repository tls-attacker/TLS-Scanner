/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import redis.clients.jedis.Jedis;

import java.util.Collection;
import java.util.UUID;

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

    public UUID getScanTask() {
        // TODO: retrieve scan task from redis
        return null;
    }

    @Override
    public Collection<UUID> getScanTasks(int quantity) {
        // TODO: retrieve qty scan tasks
        return null;
    }

    public void addScanTask(UUID task) {
        // TODO: write scan task to redis
    }
}
