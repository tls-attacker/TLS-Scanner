/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.config.delegate;

import com.beust.jcommander.Parameter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author robert
 */
public class MongoDbDelegate {

    private static final Logger LOGGER = LogManager.getLogger();

    @Parameter(names = "-mongoDbHost", description = "Host of the MongoDB instance this crawler saves to.")
    private String mongoDbHost;

    @Parameter(names = "-mongoDbPort", description = "Port of the MongoDB instance this crawler saves to.")
    private int mongoDbPort;

    @Parameter(names = "-mongoDbUser", description = "The username to be used to authenticate with the MongoDB instance.")
    private String mongoDbUser;

    @Parameter(names = "-mongoDbPass", description = "The passwort to be used to authenticate with MongoDB.")
    private String mongoDbPass;

    @Parameter(names = "-mongoDbAuthSource", description = "The DB within the MongoDB instance, in which the user:pass is defined.")
    private String mongoDbAuthSource;

    public MongoDbDelegate() {
    }

    public String getMongoDbHost() {
        return mongoDbHost;
    }

    public void setMongoDbHost(String mongoDbHost) {
        this.mongoDbHost = mongoDbHost;
    }

    public int getMongoDbPort() {
        return mongoDbPort;
    }

    public void setMongoDbPort(int mongoDbPort) {
        this.mongoDbPort = mongoDbPort;
    }

    public String getMongoDbUser() {
        return mongoDbUser;
    }

    public void setMongoDbUser(String mongoDbUser) {
        this.mongoDbUser = mongoDbUser;
    }

    public String getMongoDbPass() {
        return mongoDbPass;
    }

    public void setMongoDbPass(String mongoDbPass) {
        this.mongoDbPass = mongoDbPass;
    }

    public String getMongoDbAuthSource() {
        return mongoDbAuthSource;
    }

    public void setMongoDbAuthSource(String mongoDbAuthSource) {
        this.mongoDbAuthSource = mongoDbAuthSource;
    }

}
