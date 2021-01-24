/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.config.delegate;

import com.beust.jcommander.Parameter;
import lombok.Getter;

/**
 * @author robert
 */
@Getter
public class MongoDbDelegate {


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


}
