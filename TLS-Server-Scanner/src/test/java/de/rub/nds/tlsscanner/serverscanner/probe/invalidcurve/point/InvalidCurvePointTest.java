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
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.FieldElementFp;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class InvalidCurvePointTest {

    /** Test points of small order. */
    @Test
    public void testSmallOrder() {
        List<NamedGroup> knownGroups = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        for (NamedGroup group : knownGroups) {
            assertTrue(pointsForGroupAreOrdered(group));
            InvalidCurvePoint invP = InvalidCurvePoint.smallOrder(group);
            if (invP != null) {
                assertEquals(group, invP.getNamedGroup());
                assertTrue(isOrderCorrect(invP));
            }
        }
    }

    /** Test points of alternative order. */
    @Test
    public void testAlternativeOrder() {
        List<NamedGroup> knownGroups = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        for (NamedGroup group : knownGroups) {
            assertTrue(pointsForGroupAreOrdered(group));
            InvalidCurvePoint invP = InvalidCurvePoint.alternativeOrder(group);
            if (invP != null) {
                assertEquals(group, invP.getNamedGroup());
                assertTrue(isOrderCorrect(invP));
            }
        }
    }

    /** Test points of large order. */
    @Test
    public void testLargeOrder() {
        List<NamedGroup> knownGroups = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        for (NamedGroup group : knownGroups) {
            assertTrue(pointsForGroupAreOrdered(group));
            InvalidCurvePoint invP = InvalidCurvePoint.largeOrder(group);
            if (invP != null) {
                assertEquals(group, invP.getNamedGroup());
                assertTrue(isOrderCorrect(invP));
            }
        }
    }

    private boolean isOrderCorrect(InvalidCurvePoint invP) {
        EllipticCurve curve =
                (((NamedEllipticCurveParameters) invP.getNamedGroup().getGroupParameters()))
                        .getGroup();
        FieldElementFp bX = new FieldElementFp(invP.getPublicPointBaseX(), curve.getModulus());
        FieldElementFp bY = new FieldElementFp(invP.getPublicPointBaseY(), curve.getModulus());
        Point point = new Point(bX, bY);

        if (invP.getOrder().isProbablePrime(100)) {
            Point res = curve.mult(invP.getOrder(), point);
            return res.isAtInfinity();
        } else {
            for (int i = 1; i <= invP.getOrder().intValue(); i++) {
                Point res = curve.mult(BigInteger.valueOf(i), point);
                if (res.isAtInfinity()) {
                    return i == invP.getOrder().intValue();
                }
            }
        }
        return false;
    }

    private boolean pointsForGroupAreOrdered(NamedGroup group) {
        InvalidCurvePoint invP1 = InvalidCurvePoint.smallOrder(group);
        InvalidCurvePoint invP2 = InvalidCurvePoint.alternativeOrder(group);
        InvalidCurvePoint invP3 = InvalidCurvePoint.largeOrder(group);

        if (invP1 == null && (invP2 != null || invP3 != null)) {
            return false;
        } else if (invP2 == null && invP3 != null) {
            return false;
        } else if (invP2 != null
                && invP1 != null
                && invP1.getOrder().compareTo(invP2.getOrder()) >= 0) {
            return false;
        } else if (invP3 != null
                && invP2 != null
                && invP2.getOrder().compareTo(invP3.getOrder()) >= 0) {
            return false;
        }
        return true;
    }
}
