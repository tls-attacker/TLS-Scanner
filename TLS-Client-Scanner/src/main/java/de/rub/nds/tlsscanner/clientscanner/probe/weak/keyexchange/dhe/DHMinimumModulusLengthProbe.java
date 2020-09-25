package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseStatefulProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHMinimumModulusLengthProbe.DHWeakModulusState;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class DHMinimumModulusLengthProbe extends BaseStatefulDHEProbe<DHWeakModulusState> {
    private static final int BITLENGTH_CUTOFF_LB = 2; // BigInt cannot handle bitLength<2
    private static final int BITLENGTH_CUTOFF_UB = 4096; // Performance gets too slow
    private static final Logger LOGGER = LogManager.getLogger();

    public DHMinimumModulusLengthProbe(IOrchestrator orchestrator) {
        super(orchestrator);
    }

    @Override
    protected DHWeakModulusState getDefaultState(DispatchInformation dispatchInformation) {
        return new DHWeakModulusState(1024);
    }

    @Override
    protected DHWeakModulusState execute(State state, DispatchInformation dispatchInformation, DHWeakModulusState internalState) {
        Config config = state.getConfig();
        Integer toTest = internalState.getNext();
        LOGGER.debug("Testing {}", toTest);
        BaseDHEFunctionality.prepareConfig(config);
        config.setDefaultApplicationMessageData("Keysize: " + toTest);
        config.setDefaultServerDhModulus(new BigInteger(toTest, 10, new Random()));
        extendWorkflowTraceToApplication(state.getWorkflowTrace(), config);
        executeState(state, dispatchInformation);
        internalState.put(toTest, state);
        return internalState;
    }

    public static class DHWeakModulusState implements BaseStatefulProbe.InternalProbeState {
        private boolean wasGreedy = false;

        private Integer highestRejected;
        private Integer lowestAccepted;
        private final int startingPoint;

        public DHWeakModulusState(int startingPoint) {
            this.startingPoint = startingPoint;
        }

        public int getNext() {
            if (highestRejected == null && lowestAccepted == null) {
                return startingPoint;
            }
            if (lowestAccepted == null) {
                // we have no upper bound, i.e. we were always rejected -> try to double
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
        private final Integer lowestBitlengthAccepted;
        private final boolean cutoffKickedIn;

        public DHMinimumModulusLengthResult(Integer result, boolean cutoffKickedIn) {
            this.lowestBitlengthAccepted = result;
            this.cutoffKickedIn = cutoffKickedIn;
        }

        @Override
        public void merge(ClientReport report) {
            report.putResult(DHMinimumModulusLengthProbe.class, this);
        }

    }
}
