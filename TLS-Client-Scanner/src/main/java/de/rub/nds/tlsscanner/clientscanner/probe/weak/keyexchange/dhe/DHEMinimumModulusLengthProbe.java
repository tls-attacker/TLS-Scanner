/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import java.math.BigInteger;
import java.util.Random;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseStatefulProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHEMinimumModulusLengthProbe.DHEWeakModulusState;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

//cf. logjam
public class DHEMinimumModulusLengthProbe extends BaseStatefulDHEProbe<DHEWeakModulusState> {
    // Primes with less than two bits (i.e. less than two) are quite "rare"
    private static final int BITLENGTH_CUTOFF_LB = 2;
    // Performance gets too slow
    private static final int BITLENGTH_CUTOFF_UB = 4096;
    private static final Logger LOGGER = LogManager.getLogger();

    private Random rnd = new Random();

    public DHEMinimumModulusLengthProbe(Orchestrator orchestrator) {
        super(orchestrator, false, false, true);
    }

    @Override
    protected DHEWeakModulusState getDefaultState() {
        return new DHEWeakModulusState(1024);
    }

    @Override
    protected DHEWeakModulusState execute(State state, DispatchInformation dispatchInformation,
            DHEWeakModulusState internalState) throws DispatchException {
        Config config = state.getConfig();
        Integer toTest = internalState.getNext();
        LOGGER.debug("Testing {}", toTest);
        prepareConfig(config);
        config.setDefaultApplicationMessageData("Keysize: " + toTest);
        config.setDefaultServerDhModulus(new BigInteger(toTest, 10, rnd));
        extendWorkflowTraceToApplication(state.getWorkflowTrace(), config, false);
        executeState(state, dispatchInformation);
        internalState.put(toTest, state);
        return internalState;
    }

    public static class DHEWeakModulusState implements BaseStatefulProbe.InternalProbeState {
        private boolean wasGreedy = false;

        private Integer highestRejected;
        private Integer lowestAccepted;
        private final int startingPoint;

        public DHEWeakModulusState(int startingPoint) {
            this.startingPoint = startingPoint;
        }

        public int getNext() {
            if (highestRejected == null && lowestAccepted == null) {
                return startingPoint;
            }
            if (lowestAccepted == null) {
                // we have no upper bound, i.e. we were always rejected -> try
                // to double
                return highestRejected * 2;
            } else {
                // we have an upper bound (and lower bound is at least 0)
                if (highestRejected != null && !wasGreedy) {
                    // be greedy and test if upperbound-1 is rejected
                    // we only do this the first time we have both bounds
                    wasGreedy = true;
                    return lowestAccepted - 1;
                } else {
                    int lb = highestRejected == null ? 0 : highestRejected;
                    int ub = lowestAccepted;
                    return (lb + (ub - lb) / 2);
                }
            }
        }

        public void put(int bitlength, State state) {
            // validate bitlength and set new bounds
            if (didAccept(state)) {
                if (lowestAccepted != null && bitlength >= lowestAccepted) {
                    throw new IllegalArgumentException("Invalid (accepted) bitlength");
                }
                lowestAccepted = bitlength;
            } else {
                if (highestRejected != null && bitlength <= highestRejected) {
                    throw new IllegalArgumentException("Invalid (rejected) bitlength");
                }
                highestRejected = bitlength;
            }
        }

        private boolean didAccept(State state) {
            return state.getWorkflowTrace().executedAsPlanned();
        }

        @Override
        public boolean isDone() {
            if (lowestAccepted == null) {
                return highestRejected >= BITLENGTH_CUTOFF_UB;
            } else if (highestRejected == null) {
                return lowestAccepted <= BITLENGTH_CUTOFF_LB;
            } else {
                return lowestAccepted - highestRejected <= 1;
            }
        }

        @Override
        public ClientProbeResult toResult() {
            boolean didCutoff = false;
            if (highestRejected != null) {
                didCutoff = didCutoff || highestRejected >= BITLENGTH_CUTOFF_UB;
            }
            if (lowestAccepted != null) {
                didCutoff = didCutoff || lowestAccepted <= BITLENGTH_CUTOFF_LB;
            }
            return new DHMinimumModulusLengthResult(lowestAccepted, didCutoff);
        }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class DHMinimumModulusLengthResult extends ClientProbeResult {
        public final Integer lowestBitlengthAccepted;
        public final boolean cutoffKickedIn;

        public DHMinimumModulusLengthResult(Integer result, boolean cutoffKickedIn) {
            this.lowestBitlengthAccepted = result;
            this.cutoffKickedIn = cutoffKickedIn;
        }

        @Override
        public void merge(ClientReport report) {
            report.putResult(DHEMinimumModulusLengthProbe.class, this);
        }

    }
}
