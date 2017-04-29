/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.report.check.CheckType;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CiphersuiteOrderProbe extends TLSProbe {

    public CiphersuiteOrderProbe(ScannerConfig config) {
        super("CiphersuiteOrder", config);
    }

    @Override
    public ProbeResult call() {
        LOGGER.debug("Starting CipherSuiteOrder Test");

        List<CipherSuite> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(CipherSuite.values()));
        toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
        CipherSuite firstSelectedCipherSuite = getSelectedCipherSuite(toTestList);
        Collections.reverseOrder();
        CipherSuite secondSelectedCipherSuite = getSelectedCipherSuite(toTestList);

        List<ResultValue> resultList = new LinkedList<>();
        resultList.add(new ResultValue("Server Enforces Ciphersuite Order", ""
                + (firstSelectedCipherSuite == secondSelectedCipherSuite)));
        List<TLSCheck> checkList = new LinkedList<>();
        checkList.add(new TLSCheck(firstSelectedCipherSuite != secondSelectedCipherSuite,
                CheckType.CIPHERSUITEORDER_ENFORCED, getConfig().getLanguage()));
        return new ProbeResult(getProbeName(), "Der Server wählt CipherSuites selbst", resultList, checkList);

    }

    public CipherSuite getSelectedCipherSuite(List<CipherSuite> toTestList) {

        TlsConfig tlsConfig = getConfig().createConfig();
        tlsConfig.setSupportedCiphersuites(toTestList);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setAddServerNameIndicationExtension(false);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgrorithmsExtension(true);
        List<NamedCurve> namedCurves = Arrays.asList(NamedCurve.values());

        tlsConfig.setNamedCurves(namedCurves);
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage(tlsConfig);
        trace.add(new SendAction(message));
        trace.add(new ReceiveAction(new ArbitraryMessage()));
        tlsConfig.setWorkflowTrace(trace);
        TlsContext tlsContext = new TlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(),
                tlsContext);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            ex.printStackTrace();
        }
        return tlsContext.getSelectedCipherSuite();
    }
}
