/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.data.ScanTarget;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import java.net.ConnectException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.net.util.SubnetUtils.SubnetInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An orchestration provider implementation using Redis as an external source.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class RedisOrchestrationProvider implements IOrchestrationProvider {

    private final static Logger LOG = LogManager.getLogger();

    private final static int REDIS_TIMEOUT = 30000; // in ms

    private boolean initialized = false;

    private final String redisHost;
    private final int redisPort;
    private final String redisPass;

    private JedisPool jedisPool;

    private String blackListName = null;

    private Set<String> ipBlackListSet = null;
    private List<SubnetInfo> cidrBlackList = null;

    public RedisOrchestrationProvider(String redisHost, int redisPort, String redisPass) {
        this.redisHost = redisHost;
        this.redisPort = redisPort;
        this.redisPass = redisPass;
    }

    public void init(String blackListName) throws ConnectException {
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

        this.blackListName = blackListName;
        this.initialized = true;
        LOG.info("Initializing Blacklist");
        updateBlacklist();
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
    public String getScanTask(ScanJob job) {
        this.checkInit();

        LOG.trace("getScanTask()");

        String result;
        try (Jedis jedis = this.jedisPool.getResource()) {
            result = jedis.rpop(job.getWorkspace());
        }

        return result;
    }

    @Override
    public long getNumberOfTasks(ScanJob job) {
        this.checkInit();

        long listLength;
        try (Jedis redis = this.jedisPool.getResource()) {
            listLength = redis.scard(job.getWorkspace());
        }
        return listLength;
    }

    @Override
    public Collection<String> getScanTasks(ScanJob job, int quantity) {
        this.checkInit();
        Collection<String> result = new ArrayList<>(quantity);
        try (Jedis jedis = this.jedisPool.getResource()) {
            Set<String> scanTaskIds = jedis.spop(job.getWorkspace(), quantity);
            return scanTaskIds;
        }
    }

    @Override
    public void addScanTask(ScanJob job, String taskId) {
        this.checkInit();

        LOG.trace("addScanTask()");

        try (Jedis jedis = this.jedisPool.getResource()) {
            jedis.sadd(job.getWorkspace(), taskId);
        }
    }

    @Override
    public void addScanTasks(ScanJob job, Collection<String> hosts) {
        this.checkInit();

        LOG.trace("addScanTasks()");
        if (hosts.size() > 500000) {
            //Redis does not allow really really big inserstions - we need to split this up : /
            final Collection<String> subList = new LinkedList<>();
            hosts.forEach(next -> {
                subList.add(next);
                if (subList.size() == 500000) {
                    addScanTasks(job, subList);
                    subList.clear();
                }
            });
        } else {
            String[] tids = hosts.toArray(new String[hosts.size()]);

            try (Jedis jedis = this.jedisPool.getResource()) {
                jedis.sadd(job.getWorkspace(), tids);
            }
        }
    }

    @Override
    public synchronized boolean isBlacklisted(ScanTarget target) {
        if (ipBlackListSet.contains(target.getIp())) {
            return true;
        }
        for (SubnetInfo subnetInfo : cidrBlackList) {
            if (subnetInfo.isInRange(target.getIp())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public synchronized void updateBlacklist() {
        ipBlackListSet = new HashSet<>();
        cidrBlackList = new LinkedList<>();
        try (Jedis jedis = this.jedisPool.getResource()) {
            List<String> tempBlacklistStrings = jedis.lrange(blackListName, 0, -1);
            for (String blackListEntry : tempBlacklistStrings) {
                if (tempBlacklistStrings.contains("/")) {
                    SubnetUtils utils = new SubnetUtils(blackListEntry);
                    cidrBlackList.add(utils.getInfo());
                } else {
                    ipBlackListSet.add(blackListEntry);
                }
            }
            LOG.info("Blacklist now contains: {}", tempBlacklistStrings.size());
        }
    }

    @Override
    public Collection<ScanJob> getScanJobs() {
        this.checkInit();

        LOG.trace("getScanJobs()");
        List<String> activeJobs;
        try (Jedis jedis = this.jedisPool.getResource()) {
            activeJobs = jedis.lrange("crawling-jobs", 0l, -1l);
        }
        ObjectMapper mapper = new ObjectMapper();
        List<ScanJob> scanJobList = new LinkedList<>();
        for (String job : activeJobs) {
            try {
                ScanJob readJob = mapper.readValue(job, ScanJob.class);
                scanJobList.add(readJob);
            } catch (JsonProcessingException ex) {
                ex.printStackTrace();
                LOG.warn("Invalid active job:\n" + job);
            }
        }
        return scanJobList;
    }

    @Override
    public void putScanJob(ScanJob job) {
        ObjectMapper mapper = new ObjectMapper();

        try (Jedis jedis = this.jedisPool.getResource()) {
            jedis.lpush("crawling-jobs", mapper.writeValueAsString(job));
        } catch (JsonProcessingException ex) {
            LOG.warn("Could not add ScanJob to Redis");
        }
    }

    @Override
    public void deleteScanJob(ScanJob job) {
        ObjectMapper mapper = new ObjectMapper();

        try (Jedis jedis = this.jedisPool.getResource()) {
            jedis.lrem("crawling-jobs", 1, mapper.writeValueAsString(job));
        } catch (JsonProcessingException ex) {
            LOG.warn("Could not remove ScanJob from Redis");
        }
    }
}
