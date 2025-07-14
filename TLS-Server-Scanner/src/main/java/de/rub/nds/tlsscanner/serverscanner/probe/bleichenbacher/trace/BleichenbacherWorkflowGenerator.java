/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.trace;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.constans.BleichenbacherWorkflowType;

public class BleichenbacherWorkflowGenerator {

    private BleichenbacherWorkflowGenerator() {}

    /**
     * Generates a workflow trace for Bleichenbacher attack testing with the specified configuration
     * and encrypted premaster secret.
     *
     * @param tlsConfig The TLS configuration to use for the workflow
     * @param type The type of Bleichenbacher workflow to generate (CKE, CKE_CCS, CKE_CCS_FIN, or
     *     CKE_FIN)
     * @param encryptedPMS The encrypted premaster secret to use in the RSA client key exchange
     * @return A WorkflowTrace configured for the specified Bleichenbacher attack test scenario
     */
    public static WorkflowTrace generateWorkflow(
            Config tlsConfig, BleichenbacherWorkflowType type, byte[] encryptedPMS) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(tlsConfig)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        RSAClientKeyExchangeMessage cke = new RSAClientKeyExchangeMessage();
        ModifiableByteArray epms = new ModifiableByteArray();
        epms.setModifications(new ByteArrayExplicitValueModification(encryptedPMS));
        cke.setPublicKey(epms);
        if (null != type) {
            switch (type) {
                case CKE:
                    trace.addTlsAction(new SendAction(cke));
                    break;
                case CKE_CCS:
                    trace.addTlsAction(new SendAction(cke, new ChangeCipherSpecMessage()));
                    break;
                case CKE_CCS_FIN:
                    trace.addTlsAction(
                            new SendAction(
                                    cke, new ChangeCipherSpecMessage(), new FinishedMessage()));
                    break;
                case CKE_FIN:
                    trace.addTlsAction(new SendAction(cke, new FinishedMessage()));
                    break;
                default:
                    break;
            }
        }
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }
}
