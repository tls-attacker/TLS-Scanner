/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import static de.rub.nds.tlsscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.StarttlsResult;


public class StarttlsProbe extends TlsProbe {

    public StarttlsProbe(ScannerConfig config) {
        super(ProbeType.STARTTLS, config, 0);
    }

    @Override
    public ProbeResult executeTest() {
        Config tlsConfig = getScannerConfig().createConfig();
        
        if(getScannerConfig().getStarttlsType() != null && !getScannerConfig().getStarttlsType().isEmpty()) {
            switch(getScannerConfig().getStarttlsType()) {
                case "ftp": {
                    tlsConfig.setStarttlsType(StarttlsType.FTP);
                    break;
                }
                case "imap": {
                    tlsConfig.setStarttlsType(StarttlsType.IMAP);
                    break;
                }
                case "pop3": {
                    tlsConfig.setStarttlsType(StarttlsType.POP3);
                    break;
                }
                case "smtp": {
                    tlsConfig.setStarttlsType(StarttlsType.SMTP);
                    break;
                }
            }
        }
        State state = new State(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT,state);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.debug(ex);
        }
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            LOGGER.debug("Started TLS Negotiation.");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return new StarttlsResult(true);
        } else {
            LOGGER.debug("Did not start TLS Negotiation.");
            return new StarttlsResult(false);
        }
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return null;
    }
    
}
