/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.utility;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.net.ConnectException;
import java.util.Iterator;

/**
 * Address Iterator reading scan targets from redis.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class RedisAddressSource implements IAddressIterator {
    private static Logger LOG = LoggerFactory.getLogger(RedisAddressSource.class);

    private boolean initialized;
    private String redisConnString;
    private String listKey;
    private JedisPool jedisPool;

    /**
     * Package private, should be build through the factory.
     */
    RedisAddressSource(String connectionString, String listKey) {
        this.redisConnString = connectionString;
        this.listKey = listKey;
        this.initialized = false;
    }

    public void init() throws ConnectException {
        this.jedisPool = new JedisPool(this.redisConnString);

        try (Jedis jedis = this.jedisPool.getResource()) {
            if (jedis.isConnected()) {
                LOG.info("Connected to Redis at " +
                        (this.redisConnString.equals("") ? "localhost" : this.redisConnString));
            } else {
                LOG.error("Connecting to Redis failed.");
                throw new ConnectException("Could not connect to Redis endpoint.");
            }
        }

        this.initialized = true;
    }

    /**
     * Convenience method to block method entry in situations where the iterator is not initialized.
     */
    private void checkInit() {
        if (!this.initialized) {
            String error = String.format("%s has not been initialized.",
                    RedisAddressSource.class.getName());

            LOG.error(error);
            throw new RuntimeException(error);
        }
    }

    @Override
    public boolean hasNext() {
        this.checkInit();

        boolean result;

        try (Jedis redis = this.jedisPool.getResource()) {
            result = redis.llen(this.listKey) > 0;
        }

        return result;
    }

    @Override
    public String next() {
        this.checkInit();

        String result;

        try (Jedis redis = this.jedisPool.getResource()) {
            result = redis.rpop(this.listKey);
        }

        return result;
    }

    @Override
    public void remove() {
        throw new RuntimeException("Illegal Action.");
    }

    @Override
    public Iterator<String> iterator() {
        return this;
    }
}
