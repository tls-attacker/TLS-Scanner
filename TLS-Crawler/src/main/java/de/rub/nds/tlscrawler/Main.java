/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlscrawler.config.ControllerCommandConfig;
import de.rub.nds.tlscrawler.config.WorkerCommandConfig;
import de.rub.nds.tlscrawler.core.Controller;
import de.rub.nds.tlscrawler.core.Worker;
import de.rub.nds.tlscrawler.orchestration.RabbitMqOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.MongoPersistenceProvider;

/**
 * TLS-Crawler's main class.
 */
public class Main {

    public static void main(String[] args) {
        JCommander jc = new JCommander();

        ControllerCommandConfig controllerCommandConfig = new ControllerCommandConfig();
        jc.addCommand("controller", controllerCommandConfig);

        WorkerCommandConfig workerCommandConfig = new WorkerCommandConfig();
        jc.addCommand("worker", workerCommandConfig);

        jc.parse(args);
        if (jc.getParsedCommand() == null) {
            jc.usage();
            return;
        }

        switch (jc.getParsedCommand().toLowerCase()) {
            case "worker":
                Worker worker = new Worker(workerCommandConfig, new RabbitMqOrchestrationProvider(workerCommandConfig.getRabbitMqDelegate()),
                    new MongoPersistenceProvider(workerCommandConfig.getMongoDbDelegate()));
                worker.start();
                break;
            case "controller":
                controllerCommandConfig.validate();
                Controller controller = new Controller(controllerCommandConfig, new RabbitMqOrchestrationProvider(controllerCommandConfig.getRabbitMqDelegate()),
                    new MongoPersistenceProvider(controllerCommandConfig.getMongoDbDelegate()));
                controller.start();
                break;
            default:
                jc.usage();
        }
    }

}
