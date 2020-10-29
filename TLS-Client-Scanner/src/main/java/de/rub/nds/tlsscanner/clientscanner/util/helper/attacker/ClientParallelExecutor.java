package de.rub.nds.tlsscanner.clientscanner.util.helper.attacker;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Future;

import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;

public class ClientParallelExecutor extends ParallelExecutor {
    public static final Map<Class<? extends TlsTask>, ITaskTransformer> taskReplacementMap = new HashMap<>();

    static {
        taskReplacementMap.put(FingerPrintTask.class, ClientFingerprintTask::new);
    }

    public final IOrchestrator orchestrator;
    public final ClientReport report;
    public final String uid;
    public final String hostnamePrefix;

    public ClientParallelExecutor(IOrchestrator orchestrator, ClientReport report, String uid, String hostnamePrefix) {
        super(orchestrator.getSecondaryExecutor(), 3);
        this.orchestrator = orchestrator;
        this.report = report;
        this.uid = uid;
        this.hostnamePrefix = hostnamePrefix;
    }

    @Override
    public Future addTask(TlsTask task) {
        Class<? extends TlsTask> taskClass = task.getClass();
        ITaskTransformer transformer = taskReplacementMap.get(taskClass);
        TlsTask newTask = transformer.apply(task, this);
        return super.addTask(newTask);
    }

}
