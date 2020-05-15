/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.config.delegate;

import com.beust.jcommander.Parameter;

/**
 *
 * @author robert
 */
public class RedisDelegate {

    @Parameter(names = "-redisHost", description = "Host of the Redis instance the crawler uses to coordinate.")
    private String redisHost;

    @Parameter(names = "-redisPort", description = "Port of the Redis instance the crawler uses to coordinate.")
    private int redisPort;

    @Parameter(names = "-redisPass", description = "Password of the Redis instance the crawler uses to coordinate.")
    private String redisPass;

    @Parameter(names = "-jobQueue", description = "The name of the job queue")
    private String jobQueue = "crawling-jobs";


    public RedisDelegate() {
    }

    public String getRedisHost() {
        return redisHost;
    }

    public void setRedisHost(String redisHost) {
        this.redisHost = redisHost;
    }

    public int getRedisPort() {
        return redisPort;
    }

    public void setRedisPort(int redisPort) {
        this.redisPort = redisPort;
    }

    public String getRedisPass() {
        return redisPass;
    }

    public void setRedisPass(String redisPass) {
        this.redisPass = redisPass;
    }

    public String getJobQueue() {
        return jobQueue;
    }

    public void setJobQueue(String jobQueue) {
        this.jobQueue = jobQueue;
    }
}
