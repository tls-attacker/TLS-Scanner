/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.config;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlscrawler.config.delegate.MongoDbDelegate;

/**
 *
 * @author robert
 */
public class AnalysisCommandConfig {

    @ParametersDelegate
    private MongoDbDelegate mongoDbDelegate;

    public AnalysisCommandConfig() {
        mongoDbDelegate = new MongoDbDelegate();
    }

    public MongoDbDelegate getMongoDbDelegate() {
        return mongoDbDelegate;
    }

}
