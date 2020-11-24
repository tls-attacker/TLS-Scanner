/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.util.helper.attacker;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Future;

import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;

public class ClientParallelExecutor extends ParallelExecutor {
    public static final Map<Class<? extends TlsTask>, ITaskTransformer> taskReplacementMap = new HashMap<>();

    static {
        taskReplacementMap.put(FingerPrintTask.class, ClientFingerprintTask::new);
    }

    public final Orchestrator orchestrator;
    public final ClientReport report;
    public final String hostnamePrefix;
    public final boolean exactHostname;

    public ClientParallelExecutor(Orchestrator orchestrator, ClientReport report, String hostnamePrefix,
            boolean exactHostname) {
        super(orchestrator.getSecondaryExecutor(), 3);
        this.orchestrator = orchestrator;
        this.report = report;
        this.hostnamePrefix = hostnamePrefix;
        this.exactHostname = exactHostname;
    }

    @Override
    public Future addTask(TlsTask task) {
        Class<? extends TlsTask> taskClass = task.getClass();
        ITaskTransformer transformer = taskReplacementMap.get(taskClass);
        TlsTask newTask = transformer.apply(task, this);
        return super.addTask(newTask);
    }

}
