/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlscrawler.config.delegate.MongoDbDelegate;
import de.rub.nds.tlscrawler.config.delegate.RedisDelegate;

/**
 *
 * @author robert
 */
public class SlaveCommandConfig {

    @Parameter(names = "-numberOfThreads", description = "Number of worker threads the crawler slave should use")
    private int numberOfThreads = 500;

    @Parameter(names = "-parallelProbeThreads", description = "Number of worker threads the crawler slave should use.")
    private int parallelProbeThreads = 200;

    @Parameter(names = "-instanceId", description = "The ID of this TLS-Crawler instance.")
    private String instanceId;

    @ParametersDelegate
    private RedisDelegate redisDelegate;

    @ParametersDelegate
    private MongoDbDelegate mongoDbDelegate;

    public SlaveCommandConfig() {
        redisDelegate = new RedisDelegate();
        mongoDbDelegate = new MongoDbDelegate();
    }

    public RedisDelegate getRedisDelegate() {
        return redisDelegate;
    }

    public MongoDbDelegate getMongoDbDelegate() {
        return mongoDbDelegate;
    }

    public int getNumberOfThreads() {
        return numberOfThreads;
    }

    public void setNumberOfThreads(int numberOfThreads) {
        this.numberOfThreads = numberOfThreads;
    }

    public int getParallelProbeThreads() {
        return parallelProbeThreads;
    }

    public void setParallelProbeThreads(int parallelProbeThreads) {
        this.parallelProbeThreads = parallelProbeThreads;
    }

    public String getInstanceId() {
        return instanceId;
    }

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }
}
