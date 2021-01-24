/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlscrawler.config.delegate.MongoDbDelegate;

/**
 * @author robert
 */
public class AnalysisCommandConfig {

    @ParametersDelegate
    private final MongoDbDelegate mongoDbDelegate;

    @Parameter(names = "-databaseName", description = "The name of the database.")
    private String databaseName;

    @Parameter(names = "-workspaceName", description = "The name of the workspace.")
    private String workspaceName;

    public AnalysisCommandConfig() {
        mongoDbDelegate = new MongoDbDelegate();
    }

    public MongoDbDelegate getMongoDbDelegate() {
        return mongoDbDelegate;
    }

    public String getDatabaseName() {
        return databaseName;
    }

    public void setDatabaseName(String databaseName) {
        this.databaseName = databaseName;
    }

    public String getWorkspaceName() {
        return workspaceName;
    }

    public void setWorkspaceName(String workspaceName) {
        this.workspaceName = workspaceName;
    }
}
