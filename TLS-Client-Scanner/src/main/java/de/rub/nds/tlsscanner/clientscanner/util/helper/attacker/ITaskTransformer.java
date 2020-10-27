package de.rub.nds.tlsscanner.clientscanner.util.helper.attacker;

import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;

public interface ITaskTransformer {
    TlsTask apply(TlsTask original, ClientParallelExecutor executorWithParameters);
}
