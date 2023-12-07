/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.EllipticCurveOverFp;
import de.rub.nds.protocol.crypto.ec.FieldElementFp;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.RFC7748Curve;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class TwistedCurvePointTest {

    @Test
    public void testSmallOrder() {
        List<NamedGroup> knownGroups = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        for (NamedGroup group : knownGroups) {
            assertTrue(pointsForGroupAreOrdered(group));
            TwistedCurvePoint invP = TwistedCurvePoint.smallOrder(group);
            if (invP != null) {
                assertEquals(group.getGroupParameters(), invP.getIntendedGroup());
                assertTrue(isOrderCorrect(invP));
            }
        }
    }

    @Test
    public void testAlternativeOrder() {
        List<NamedGroup> knownGroups = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        for (NamedGroup group : knownGroups) {
            assertTrue(pointsForGroupAreOrdered(group));
            TwistedCurvePoint invP = TwistedCurvePoint.alternativeOrder(group);
            if (invP != null) {
                assertEquals(group.getGroupParameters(), invP.getIntendedGroup());
                assertTrue(isOrderCorrect(invP));
            }
        }
    }

    @Test
    public void testLargeOrder() {
        List<NamedGroup> knownGroups = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        for (NamedGroup group : knownGroups) {
            assertTrue(pointsForGroupAreOrdered(group));
            TwistedCurvePoint invP = TwistedCurvePoint.largeOrder(group);
            if (invP != null) {
                assertEquals(group.getGroupParameters(), invP.getIntendedGroup());
                assertTrue(isOrderCorrect(invP));
            }
        }
    }

    private boolean isOrderCorrect(TwistedCurvePoint invP) {
        if (invP.getIntendedGroup() == NamedEllipticCurveParameters.CURVE_X25519
                || invP.getIntendedGroup() == NamedEllipticCurveParameters.CURVE_X448) {
            RFC7748Curve rfcCurve = (RFC7748Curve) invP.getIntendedGroup().getGroup();
            Point montgPoint =
                    rfcCurve.getPoint(invP.getPublicPointBaseX(), invP.getPublicPointBaseY());
            Point weierPoint = rfcCurve.toWeierstrass(montgPoint);
            BigInteger transformedX =
                    weierPoint
                            .getFieldX()
                            .getData()
                            .multiply(invP.getPointD())
                            .mod(rfcCurve.getModulus());

            EllipticCurveOverFp intendedCurve =
                    ((RFC7748Curve) invP.getIntendedGroup().getGroup()).getWeierstrassEquivalent();
            BigInteger modA =
                    intendedCurve
                            .getFieldA()
                            .getData()
                            .multiply(invP.getPointD().pow(2))
                            .mod(intendedCurve.getModulus());
            BigInteger modB =
                    intendedCurve
                            .getFieldB()
                            .getData()
                            .multiply(invP.getPointD().pow(3))
                            .mod(intendedCurve.getModulus());
            EllipticCurveOverFp twistedCurve =
                    new EllipticCurveOverFp(modA, modB, intendedCurve.getModulus());
            Point point =
                    Point.createPoint(
                            transformedX, invP.getPublicPointBaseY(), invP.getIntendedGroup());

            for (long i = 1; i <= invP.getOrder().longValue(); i++) {
                Point res = twistedCurve.mult(BigInteger.valueOf(i), point);
                if (res.isAtInfinity()) {
                    return i == invP.getOrder().intValue();
                }
            }
        } else {
            EllipticCurveOverFp intendedCurve =
                    (EllipticCurveOverFp) invP.getIntendedGroup().getGroup();
            BigInteger modA =
                    intendedCurve
                            .getFieldA()
                            .getData()
                            .multiply(invP.getPointD().pow(2))
                            .mod(intendedCurve.getModulus());
            BigInteger modB =
                    intendedCurve
                            .getFieldB()
                            .getData()
                            .multiply(invP.getPointD().pow(3))
                            .mod(intendedCurve.getModulus());
            EllipticCurveOverFp twistedCurve =
                    new EllipticCurveOverFp(modA, modB, intendedCurve.getModulus());

            BigInteger modX =
                    invP.getPublicPointBaseX()
                            .multiply(invP.getPointD())
                            .mod(twistedCurve.getModulus());
            FieldElementFp bX = new FieldElementFp(modX, twistedCurve.getModulus());
            FieldElementFp bY =
                    new FieldElementFp(invP.getPublicPointBaseY(), twistedCurve.getModulus());
            Point point = new Point(bX, bY);

            if (invP.getOrder().isProbablePrime(100)) {
                Point res = twistedCurve.mult(invP.getOrder(), point);
                return res.isAtInfinity();
            } else {
                for (long i = 1; i <= invP.getOrder().longValue(); i++) {
                    Point res = twistedCurve.mult(BigInteger.valueOf(i), point);
                    if (res.isAtInfinity()) {
                        return i == invP.getOrder().intValue();
                    }
                }
            }
        }
        return false;
    }

    private boolean pointsForGroupAreOrdered(NamedGroup group) {
        TwistedCurvePoint invP1 = TwistedCurvePoint.smallOrder(group);
        TwistedCurvePoint invP2 = TwistedCurvePoint.alternativeOrder(group);
        TwistedCurvePoint invP3 = TwistedCurvePoint.largeOrder(group);

        if (invP1 == null && (invP2 != null || invP3 != null)) {
            return false;
        } else if (invP2 == null && invP3 != null) {
            return false;
        } else if (invP2 != null && invP1.getOrder().compareTo(invP2.getOrder()) >= 0) {
            return false;
        } else if (invP3 != null
                && invP2 != null
                && invP2.getOrder().compareTo(invP3.getOrder()) >= 0) {
            return false;
        }
        return true;
    }
}
