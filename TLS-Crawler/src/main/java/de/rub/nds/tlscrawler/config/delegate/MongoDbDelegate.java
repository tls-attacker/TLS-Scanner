/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.config.delegate;

import com.beust.jcommander.Parameter;

public class MongoDbDelegate {

    @Parameter(names = "-mongoDbHost", description = "Host of the MongoDB instance this crawler saves to.")
    private String mongoDbHost;

    @Parameter(names = "-mongoDbPort", description = "Port of the MongoDB instance this crawler saves to.")
    private int mongoDbPort;

    @Parameter(names = "-mongoDbUser", description = "The username to be used to authenticate with the MongoDB instance.")
    private String mongoDbUser;

    @Parameter(names = "-mongoDbPass", description = "The passwort to be used to authenticate with MongoDB.")
    private String mongoDbPass;

    @Parameter(names = "-mongoDbPassFile", description = "The passwort to be used to authenticate with MongoDB.")
    private String mongoDbPassFile;

    @Parameter(names = "-mongoDbAuthSource", description = "The DB within the MongoDB instance, in which the user:pass is defined.")
    private String mongoDbAuthSource;

    public String getMongoDbHost() {
        return mongoDbHost;
    }

    public int getMongoDbPort() {
        return mongoDbPort;
    }

    public String getMongoDbUser() {
        return mongoDbUser;
    }

    public String getMongoDbPass() {
        return mongoDbPass;
    }

    public String getMongoDbPassFile() {
        return mongoDbPassFile;
    }

    public String getMongoDbAuthSource() {
        return mongoDbAuthSource;
    }
}
