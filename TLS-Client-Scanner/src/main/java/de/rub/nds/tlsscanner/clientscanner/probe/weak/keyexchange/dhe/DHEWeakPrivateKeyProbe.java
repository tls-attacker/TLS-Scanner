/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.probe.VersionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHEWeakPrivateKeyProbe.DHWeakPrivateKeyProbeResult;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHEWeakPrivateKeyProbe.PrivateKeyType;

public class DHEWeakPrivateKeyProbe extends BaseDHEParametrizedProbe<PrivateKeyType, DHWeakPrivateKeyProbeResult> {
    enum PrivateKeyType {
        FF_ZERO,
        FF_ONE,
        FF_SHARE_P_ONE,
        // EC_ZERO,
        // EC_ONE,
        // TLS13_ZERO,
        // TLS13_ONE,
    }

    public static Collection<DHEWeakPrivateKeyProbe> getDefaultProbes(Orchestrator orchestrator) {
        List<DHEWeakPrivateKeyProbe> ret = new ArrayList<>();
        for (PrivateKeyType pkt : PrivateKeyType.values()) {
            ret.add(new DHEWeakPrivateKeyProbe(orchestrator, pkt));
        }
        return ret;
    }

    public DHEWeakPrivateKeyProbe(Orchestrator orchestrator, PrivateKeyType keyType) {
        super(orchestrator, keyType.toString().startsWith("TLS13_"), keyType.toString().startsWith("EC_"),
            keyType.toString().startsWith("FF_"), keyType);
    }

    @Override
    public DHWeakPrivateKeyProbeResult executeInternal(State state, DispatchInformation dispatchInformation)
        throws DispatchException {
        Config config = state.getConfig();
        prepareConfig(config);
        switch (enumValue) {
            case FF_ZERO:
                // case EC_ZERO:
                // case TLS13_ZERO:
                config.setDefaultServerDhPrivateKey(BigInteger.ZERO);
                config.setDefaultServerEcPrivateKey(BigInteger.ZERO);
                break;
            case FF_ONE:
                // case EC_ONE:
                // case TLS13_ONE:
                config.setDefaultServerDhPrivateKey(BigInteger.ONE);
                config.setDefaultServerEcPrivateKey(BigInteger.ONE);
                break;
            case FF_SHARE_P_ONE:
                // A = p+1 = 1 -> a = 0
                config.setDefaultServerDhPrivateKey(BigInteger.ZERO);
                config.setDefaultServerDhPublicKey(config.getDefaultServerDhModulus().add(BigInteger.ONE));
                break;
        }
        if (enumValue.toString().startsWith("TLS13_")) {
            VersionProbe.patchConfigFor13(config);
            config.setSupportedVersions(ProtocolVersion.TLS13);
            config.setHighestProtocolVersion(ProtocolVersion.TLS13);
            config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13);
        }

        extendWorkflowTraceToApplication(state.getWorkflowTrace(), config, false);
        // trace post processing
        DHEServerKeyExchangeMessage ke = null;
        for (SendingAction action : state.getWorkflowTrace().getSendingActions()) {
            for (ProtocolMessage msg : action.getSendMessages()) {
                if (msg instanceof DHEServerKeyExchangeMessage) {
                    ke = (DHEServerKeyExchangeMessage) msg;
                    break;
                }
            }
            if (ke != null) {
                break;
            }
        }
        switch (enumValue) {
            case FF_SHARE_P_ONE:
            default:
                ke.setPublicKey(config.getDefaultServerDhPublicKey().toByteArray());
                break;
        }
        executeState(state, dispatchInformation);
        return new DHWeakPrivateKeyProbeResult(state);
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class DHWeakPrivateKeyProbeResult implements Serializable {
        public final boolean accepted;

        public DHWeakPrivateKeyProbeResult(State state) {
            accepted = state.getWorkflowTrace().executedAsPlanned();
        }

    }

}
