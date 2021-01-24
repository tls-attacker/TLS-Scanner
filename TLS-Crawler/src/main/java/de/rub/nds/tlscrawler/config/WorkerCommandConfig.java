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
import lombok.Getter;
import lombok.Setter;

/**
 * @author robert
 */
@Getter
@Setter
public class WorkerCommandConfig {

    @ParametersDelegate
    private final RedisDelegate redisDelegate;
    @ParametersDelegate
    private final MongoDbDelegate mongoDbDelegate;
    @Parameter(names = "-numberOfThreads", description = "Number of worker threads the crawler slave should use")
    private int numberOfThreads = 500;
    @Parameter(names = "-parallelProbeThreads", description = "Number of worker threads the crawler slave should use.")
    private int parallelProbeThreads = 200;
    @Parameter(names = "-instanceId", description = "The ID of this TLS-Crawler instance.")
    private String instanceId;

    public WorkerCommandConfig() {
        redisDelegate = new RedisDelegate();
        mongoDbDelegate = new MongoDbDelegate();
    }

}
