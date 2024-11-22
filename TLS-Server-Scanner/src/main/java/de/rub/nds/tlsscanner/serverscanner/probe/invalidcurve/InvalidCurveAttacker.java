/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.EcCurveEquationType;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.EllipticCurveOverFp;
import de.rub.nds.protocol.crypto.ec.FieldElementFp;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.crypto.ec.RFC7748Curve;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.core.task.InvalidCurveTask;
import de.rub.nds.tlsscanner.core.vector.response.FingerprintSecretPair;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.constants.InvalidCurveScanType;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.constants.InvalidCurveWorkflowType;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.InvalidCurvePoint;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.TwistedCurvePoint;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.trace.InvalidCurveWorkflowGenerator;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.vector.InvalidCurveVector;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.BigIntegers;

public class InvalidCurveAttacker {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ParallelExecutor executor;
    private Config tlsConfig;
    private InvalidCurveVector vector;
    private InvalidCurveScanType scanType;
    private double infinityProbability;

    private static final double ERROR_PROBABILITY = 0.0001; // increase if needed
    private static final int LARGE_ORDER_ITERATIONS = 40;
    private static final int EXTENSION_FACTOR = 7;

    private int keyOffset;
    private int protocolFlows;
    private BigInteger publicPointBaseX;
    private BigInteger publicPointBaseY;
    private ECPointFormat pointCompressionFormat;
    private BigInteger curveTwistD;

    private BigInteger premasterSecret;
    private List<FingerprintSecretPair> responsePairs;
    private List<Point> receivedEcPublicKeys;
    /**
     * All keys we received from a server in handshakes that lead to a ServerFinished - we can use
     * these to mitigate the impact of false positives in scans.
     */
    private List<Point> finishedKeys;
    /**
     * Indicates if there is a higher chance that the keys we extracted might have been sent by a
     * TLS accelerator and a TLS server behind it at the same time. (See evaluateExecutedTask)
     */
    private boolean dirtyKeysWarning;

    public InvalidCurveAttacker(
            Config baseConfig,
            ParallelExecutor executor,
            InvalidCurveVector vector,
            InvalidCurveScanType scanType,
            double infinityProbability) {
        this.tlsConfig = baseConfig;
        this.executor = executor;
        this.vector = vector;
        this.scanType = scanType;
        this.infinityProbability = infinityProbability;
        setIterationFields();
        setPublicPointFields();
        prepareConfig();
    }

    public Boolean isVulnerable() {
        responsePairs = new LinkedList<>();
        receivedEcPublicKeys = new LinkedList<>();
        finishedKeys = new LinkedList<>();
        dirtyKeysWarning = false;

        EllipticCurve curve;
        Point point;
        if (vector.isTwistAttack()) {
            curve = buildTwistedCurve();
            BigInteger transformedX;
            if (vector.getNamedGroup() == NamedGroup.ECDH_X25519
                    || vector.getNamedGroup() == NamedGroup.ECDH_X448) {
                RFC7748Curve rfcCurve = (RFC7748Curve) vector.getTargetedCurve();
                Point montgPoint = rfcCurve.getPoint(publicPointBaseX, publicPointBaseY);
                Point weierPoint = rfcCurve.toWeierstrass(montgPoint);
                transformedX =
                        weierPoint
                                .getFieldX()
                                .getData()
                                .multiply(curveTwistD)
                                .mod(curve.getModulus());
            } else {
                transformedX = publicPointBaseX.multiply(curveTwistD).mod(curve.getModulus());
            }

            point =
                    Point.createPoint(
                            transformedX,
                            publicPointBaseY,
                            (NamedEllipticCurveParameters)
                                    vector.getNamedGroup().getGroupParameters());
        } else {
            curve = vector.getTargetedCurve();
            point =
                    Point.createPoint(
                            publicPointBaseX,
                            publicPointBaseY,
                            (NamedEllipticCurveParameters)
                                    vector.getNamedGroup().getGroupParameters());
        }

        if (premasterSecret != null) {
            protocolFlows = 1;
        }

        List<TlsTask> taskList = new LinkedList<>();
        for (int i = 1; i <= protocolFlows; i++) {
            setPremasterSecret(curve, i + keyOffset, point);
            InvalidCurveTask taskToAdd =
                    new InvalidCurveTask(buildState(), executor.getReexecutions(), i + keyOffset);
            taskList.add(taskToAdd);
        }
        executor.bulkExecuteTasks(taskList);
        return evaluateExecutedTasks(taskList);
    }

    private void setPremasterSecret(EllipticCurve curve, int i, Point point) {
        BigInteger secret = new BigInteger("" + i);
        if (vector.getNamedGroup() == NamedGroup.ECDH_X25519
                || vector.getNamedGroup() == NamedGroup.ECDH_X448) {
            RFC7748Curve rfcCurve = (RFC7748Curve) vector.getTargetedCurve();
            secret = rfcCurve.decodeScalar(secret);
        }
        Point sharedPoint = curve.mult(secret, point);
        if (sharedPoint.getFieldX() == null) {
            premasterSecret = BigInteger.ZERO;
        } else {
            premasterSecret = sharedPoint.getFieldX().getData();
            if (vector.isTwistAttack()) {
                // transform back from simulated x-only ladder
                premasterSecret =
                        premasterSecret
                                .multiply(curveTwistD.modInverse(curve.getModulus()))
                                .mod(curve.getModulus());
                if (vector.getNamedGroup() == NamedGroup.ECDH_X25519
                        || vector.getNamedGroup() == NamedGroup.ECDH_X448) {
                    // transform to Montgomery domain
                    RFC7748Curve rfcCurve = (RFC7748Curve) vector.getTargetedCurve();
                    Point weierPoint =
                            rfcCurve.getPoint(premasterSecret, sharedPoint.getFieldY().getData());
                    Point montPoint = rfcCurve.toMontgomery(weierPoint);
                    premasterSecret = montPoint.getFieldX().getData();
                }
            }
            if (vector.getNamedGroup() == NamedGroup.ECDH_X25519
                    || vector.getNamedGroup() == NamedGroup.ECDH_X448) {
                // apply RFC7748 encoding
                RFC7748Curve rfcCurve = (RFC7748Curve) vector.getTargetedCurve();
                premasterSecret = new BigInteger(1, rfcCurve.encodeCoordinate(premasterSecret));
            }
        }
        LOGGER.debug(
                "PMS for scheduled Workflow Trace with secret "
                        + i
                        + ": "
                        + premasterSecret.toString());
    }

    private State buildState() {
        EllipticCurve curve = vector.getTargetedCurve();
        ModifiableByteArray serializedPublicKey =
                ModifiableVariableFactory.createByteArrayModifiableVariable();
        Point basepoint =
                new Point(
                        new FieldElementFp(publicPointBaseX, curve.getModulus()),
                        new FieldElementFp(publicPointBaseY, curve.getModulus()));
        byte[] serialized;
        if (curve instanceof RFC7748Curve) {
            serialized = ((RFC7748Curve) curve).encodeCoordinate(basepoint.getFieldX().getData());
        } else {
            serialized =
                    PointFormatter.formatToByteArray(
                            (NamedEllipticCurveParameters)
                                    vector.getNamedGroup().getGroupParameters(),
                            basepoint,
                            pointCompressionFormat.getFormat());
        }
        serializedPublicKey.setModification(ByteArrayModificationFactory.explicitValue(serialized));
        ModifiableByteArray pms = ModifiableVariableFactory.createByteArrayModifiableVariable();
        byte[] explicitPMS =
                BigIntegers.asUnsignedByteArray(
                        ArrayConverter.bigIntegerToByteArray(curve.getModulus()).length,
                        premasterSecret);
        pms.setModification(ByteArrayModificationFactory.explicitValue(explicitPMS));

        WorkflowTrace trace;
        tlsConfig.setWorkflowExecutorShouldClose(false);

        // we're modifying the config at runtime so all parallel workflow traces
        // need unique configs
        Config individualConfig = tlsConfig.createCopy();

        if (vector.isAttackInRenegotiation()) {
            trace =
                    InvalidCurveWorkflowGenerator.generateWorkflow(
                            InvalidCurveWorkflowType.RENEGOTIATION,
                            serializedPublicKey,
                            pms,
                            explicitPMS,
                            individualConfig);
        } else {
            trace =
                    InvalidCurveWorkflowGenerator.generateWorkflow(
                            InvalidCurveWorkflowType.REGULAR,
                            serializedPublicKey,
                            pms,
                            explicitPMS,
                            individualConfig);
        }

        State state = new State(individualConfig, trace);
        return state;
    }

    private EllipticCurveOverFp buildTwistedCurve() {
        EllipticCurveOverFp intendedCurve;
        if (((NamedEllipticCurveParameters) (vector.getNamedGroup().getGroupParameters()))
                        .getEquationType()
                == EcCurveEquationType.MONTGOMERY) {
            intendedCurve = ((RFC7748Curve) vector.getTargetedCurve()).getWeierstrassEquivalent();
        } else {
            intendedCurve = (EllipticCurveOverFp) vector.getTargetedCurve();
        }
        BigInteger modA =
                intendedCurve
                        .getFieldA()
                        .getData()
                        .multiply(curveTwistD.pow(2))
                        .mod(intendedCurve.getModulus());
        BigInteger modB =
                intendedCurve
                        .getFieldB()
                        .getData()
                        .multiply(curveTwistD.pow(3))
                        .mod(intendedCurve.getModulus());
        EllipticCurveOverFp twistedCurve =
                new EllipticCurveOverFp(modA, modB, intendedCurve.getModulus());
        return twistedCurve;
    }

    private Boolean evaluateExecutedTasks(List<TlsTask> taskList) {
        boolean foundExecutedAsPlanned = false;
        boolean foundServerFinished = false;

        boolean tookKeyFromSuccessfulTrace = false;
        boolean tookKeyFromUnsuccessfulTrace = false;
        for (TlsTask tlsTask : taskList) {
            InvalidCurveTask task = (InvalidCurveTask) tlsTask;
            WorkflowTrace trace = task.getState().getWorkflowTrace();
            if (!task.isHasError()) {
                foundExecutedAsPlanned = true;
                if (!(WorkflowTraceResultUtil.getLastReceivedMessage(trace) != null
                        && WorkflowTraceResultUtil.getLastReceivedMessage(trace)
                                instanceof HandshakeMessage
                        && ((HandshakeMessage)
                                                WorkflowTraceResultUtil.getLastReceivedMessage(
                                                        trace))
                                        .getHandshakeMessageType()
                                == HandshakeMessageType.FINISHED)) {
                    LOGGER.debug(
                            "Received no finished Message using secret" + task.getAppliedSecret());
                } else {
                    LOGGER.debug(
                            "Received a finished Message using secret: "
                                    + task.getAppliedSecret()
                                    + "! Server is vulnerable!");
                    finishedKeys.add(task.getReceivedEcKey());
                    foundServerFinished = true;
                }

                if (task.getReceivedEcKey() != null) {
                    tookKeyFromSuccessfulTrace = true;
                    getReceivedEcPublicKeys().add(task.getReceivedEcKey());
                }
            } else {
                if (task.getReceivedEcKey() != null) {
                    tookKeyFromUnsuccessfulTrace = true;
                    getReceivedEcPublicKeys().add(task.getReceivedEcKey());
                }
            }
            responsePairs.add(
                    new FingerprintSecretPair(task.getFingerprint(), task.getAppliedSecret()));
        }

        if (vector.isAttackInRenegotiation()
                && tookKeyFromSuccessfulTrace
                && tookKeyFromUnsuccessfulTrace) {
            /*
             * keys from an unsuccessful trace might have been extracted from the first
             * handshake of a renegotiation
             * workflow trace - it could* be more probable that this is not the same TLS
             * server as the server, which
             * answered the 2nd handshake while we can't ensure that were talking to the
             * same TLS server all the time
             * anyway, it is more important to keep an eye on this case since we're running
             * attacks in renegotiation
             * because we assume that we can bypass a TLS accelerator like this
             */
            dirtyKeysWarning = true;
        }

        if (foundExecutedAsPlanned) {
            if (foundServerFinished) {
                return true;
            } else {
                return false;
            }
        } else {
            return null;
        }
    }

    public List<FingerprintSecretPair> getResponsePairs() {
        return responsePairs;
    }

    public boolean isDirtyKeysWarning() {
        return dirtyKeysWarning;
    }

    public List<Point> getFinishedKeys() {
        return finishedKeys;
    }

    public List<Point> getReceivedEcPublicKeys() {
        return receivedEcPublicKeys;
    }

    private void setIterationFields() {
        if (vector.getNamedGroup() == NamedGroup.ECDH_X25519
                || vector.getNamedGroup() == NamedGroup.ECDH_X448) {
            protocolFlows = 1;
        } else {
            double errorAttempt = 1 - 2 * infinityProbability;
            int attempts = (int) Math.ceil(Math.log(ERROR_PROBABILITY) / Math.log(errorAttempt));

            switch (scanType) {
                case REGULAR:
                    keyOffset = 0;
                    protocolFlows = attempts;
                    break;
                case EXTENDED:
                    keyOffset = attempts;
                    protocolFlows = (attempts * EXTENSION_FACTOR) - attempts;
                    break;
                case REDUNDANT:
                    keyOffset = 0;
                    protocolFlows = attempts * EXTENSION_FACTOR;
                    break;
                case LARGE_GROUP:
                    keyOffset = 0;
                    protocolFlows = LARGE_ORDER_ITERATIONS;
                    break;
                default: // will never occur as all enum types are handled
                    ;
            }
        }
    }

    private void setPublicPointFields() {
        if (scanType == InvalidCurveScanType.REGULAR || scanType == InvalidCurveScanType.EXTENDED) {
            if (vector.isTwistAttack()) {
                curveTwistD = TwistedCurvePoint.smallOrder(vector.getNamedGroup()).getPointD();
                publicPointBaseX =
                        TwistedCurvePoint.smallOrder(vector.getNamedGroup()).getPublicPointBaseX();
                publicPointBaseY =
                        TwistedCurvePoint.smallOrder(vector.getNamedGroup()).getPublicPointBaseY();
                pointCompressionFormat = vector.getPointFormat();
            } else {
                publicPointBaseX =
                        InvalidCurvePoint.smallOrder(vector.getNamedGroup()).getPublicPointBaseX();
                publicPointBaseY =
                        InvalidCurvePoint.smallOrder(vector.getNamedGroup()).getPublicPointBaseY();
                pointCompressionFormat = ECPointFormat.UNCOMPRESSED;
            }
        } else if (scanType == InvalidCurveScanType.REDUNDANT) {
            // use second point of different order
            if (vector.isTwistAttack()) {
                curveTwistD =
                        TwistedCurvePoint.alternativeOrder(vector.getNamedGroup()).getPointD();
                publicPointBaseX =
                        TwistedCurvePoint.alternativeOrder(vector.getNamedGroup())
                                .getPublicPointBaseX();
                publicPointBaseY =
                        TwistedCurvePoint.alternativeOrder(vector.getNamedGroup())
                                .getPublicPointBaseY();
                pointCompressionFormat = vector.getPointFormat();
            } else {
                publicPointBaseX =
                        InvalidCurvePoint.alternativeOrder(vector.getNamedGroup())
                                .getPublicPointBaseX();
                publicPointBaseY =
                        InvalidCurvePoint.alternativeOrder(vector.getNamedGroup())
                                .getPublicPointBaseY();

                pointCompressionFormat = ECPointFormat.UNCOMPRESSED;
            }
        } else if (scanType == InvalidCurveScanType.LARGE_GROUP) {
            // point of large order
            if (vector.isTwistAttack()) {
                curveTwistD = TwistedCurvePoint.largeOrder(vector.getNamedGroup()).getPointD();
                publicPointBaseX =
                        TwistedCurvePoint.largeOrder(vector.getNamedGroup()).getPublicPointBaseX();
                publicPointBaseY =
                        TwistedCurvePoint.largeOrder(vector.getNamedGroup()).getPublicPointBaseY();
                pointCompressionFormat = vector.getPointFormat();
            } else {
                publicPointBaseX =
                        InvalidCurvePoint.largeOrder(vector.getNamedGroup()).getPublicPointBaseX();
                publicPointBaseY =
                        InvalidCurvePoint.largeOrder(vector.getNamedGroup()).getPublicPointBaseY();
                pointCompressionFormat = ECPointFormat.UNCOMPRESSED;
            }
        }
    }

    private void prepareConfig() {
        if (vector.getProtocolVersion().isTLS13()) {
            List<NamedGroup> keyShareGroups = new LinkedList<>();
            keyShareGroups.add(vector.getNamedGroup());
            tlsConfig.setDefaultClientKeyShareNamedGroups(keyShareGroups);
            tlsConfig.setAddPSKKeyExchangeModesExtension(true);
            List<PskKeyExchangeMode> pskKex = new LinkedList<>();
            pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
            tlsConfig.setPSKKeyExchangeModes(pskKex);
        }
        tlsConfig.setHighestProtocolVersion(vector.getProtocolVersion());
        tlsConfig.setDefaultClientSupportedCipherSuites(vector.getCipherSuite());
        tlsConfig.setDefaultClientNamedGroups(vector.getNamedGroup());
        // avoid cases where the server requires an additional group
        // to sign a PK of our test group using ECDSA
        if (!vector.getEcdsaRequiredGroups().isEmpty()) {
            tlsConfig.getDefaultClientNamedGroups().addAll(vector.getEcdsaRequiredGroups());
        }
        tlsConfig.setStopReceivingAfterFatal(false);
        tlsConfig.setStopActionsAfterFatal(false);
        tlsConfig.setStopActionsAfterWarning(false);
        tlsConfig.setWorkflowExecutorShouldClose(false);
    }
}
