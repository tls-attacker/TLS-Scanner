/*
 * Copyright 2022 nk.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;

import de.rub.nds.tlsscanner.clientscanner.probe.result.ClientRecordFragmentationResult;
/**
 *
 * 
 */
public class ClientRecordFragmentationProbe extends TlsProbe<ClientScannerConfig, ClientReport, ClientRecordFragmentationResult>{
    
    public ClientRecordFragmentationProbe(ClientScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.RECORD_FRAGMENTATION, scannerConfig);
    }

    @Override
    public ClientRecordFragmentationResult executeTest() {
        Config config = getScannerConfig().createConfig();
        config.setDefaultMaxRecordData(50);

        State state = new State(config, new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER));

        executeState(state);

        return new ClientRecordFragmentationResult(
            WorkflowTraceUtil.didSendMessage(HandshakeMessageType.SERVER_HELLO_DONE, state.getWorkflowTrace()));
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return true;
    }

    @Override
    public ClientRecordFragmentationResult getCouldNotExecuteResult() {
        return new ClientRecordFragmentationResult(null);
    }

    @Override
    public void adjustConfig(ClientReport report) {

    }
    
}
