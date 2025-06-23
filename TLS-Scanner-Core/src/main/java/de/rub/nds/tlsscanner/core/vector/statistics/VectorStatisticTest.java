/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.statistics;

import de.rub.nds.tlsscanner.core.vector.Vector;
import de.rub.nds.tlsscanner.core.vector.VectorResponse;
import de.rub.nds.tlsscanner.core.vector.response.EqualityError;
import de.rub.nds.tlsscanner.core.vector.response.FingerprintChecker;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstract base class for statistical tests on vector responses. Provides functionality to analyze
 * response patterns across different input vectors and determine if there are statistically
 * significant differences.
 *
 * @param <TestInfoT> The type of test information associated with this test
 */
public abstract class VectorStatisticTest<TestInfoT extends TestInfo> {

    /** The p-value threshold for determining statistical significance */
    protected static final double P_VALUE_SIGNIFICANCE_BORDER = 0.05;

    /** Logger instance for this class */
    protected static final Logger LOGGER = LogManager.getLogger();

    /** List of vector containers holding responses for each distinct vector */
    protected final List<VectorContainer> vectorContainerList;

    /** Information about the test being performed */
    protected final TestInfoT testInfo;

    /** The computed p-value for this test */
    protected double valueP;

    /** Indicates whether distinct answers were observed */
    protected boolean distinctAnswers;

    /** Indicates whether the distinct answers are statistically significant */
    protected boolean significantDistinctAnswers;

    /**
     * Creates a new vector statistic test with the given test information and response list.
     *
     * @param testInfo Information about the test being performed
     * @param responseList List of vector responses to analyze
     */
    public VectorStatisticTest(TestInfoT testInfo, List<VectorResponse> responseList) {
        this.testInfo = testInfo;
        vectorContainerList = new LinkedList<>();
        HashMap<Vector, List<ResponseFingerprint>> vectorMap = new HashMap<>();
        for (VectorResponse response : responseList) {
            if (vectorMap.containsKey(response.getVector())) {
                vectorMap.get(response.getVector()).add(response.getFingerprint());
            } else {
                LinkedList<ResponseFingerprint> tempResponseList = new LinkedList<>();
                tempResponseList.add(response.getFingerprint());
                vectorMap.put(response.getVector(), tempResponseList);
            }
        }
        for (Vector vector : vectorMap.keySet()) {
            List<ResponseFingerprint> tempResponseList = vectorMap.get(vector);
            vectorContainerList.add(new VectorContainer(vector, tempResponseList));
        }
    }

    /**
     * Returns whether distinct answers were observed in the test.
     *
     * @return true if distinct answers were observed, false otherwise
     */
    public boolean isDistinctAnswers() {
        return distinctAnswers;
    }

    /**
     * Returns whether the distinct answers are statistically significant.
     *
     * @return true if distinct answers are significant (p-value smaller 0.05), false otherwise
     */
    public boolean isSignificantDistinctAnswers() {
        return significantDistinctAnswers;
    }

    /**
     * Returns the computed p-value for this test.
     *
     * @return The p-value
     */
    public double getValueP() {
        return valueP;
    }

    /**
     * Returns the test information associated with this test.
     *
     * @return The test information
     */
    public TestInfoT getTestInfo() {
        return testInfo;
    }

    /**
     * Returns the list of vector containers holding response data.
     *
     * @return List of vector containers
     */
    public List<VectorContainer> getVectorContainerList() {
        return vectorContainerList;
    }

    /**
     * Returns the vector container for a specific vector.
     *
     * @param vector The vector to look up
     * @return The vector container for the specified vector, or null if not found
     */
    public VectorContainer getVectorContainer(Vector vector) {
        for (VectorContainer container : vectorContainerList) {
            if (container.getVector().equals(vector)) {
                return container;
            }
        }
        return null;
    }

    /**
     * Returns a set of all unique vectors in this test.
     *
     * @return Set of all vectors
     */
    public Set<Vector> getAllVectors() {
        Set<Vector> vectorSet = new HashSet<>();
        for (VectorContainer vectorContainer : vectorContainerList) {
            vectorSet.add(vectorContainer.getVector());
        }
        return vectorSet;
    }

    /**
     * Returns a set of all unique response fingerprints across all vectors.
     *
     * @return Set of all response fingerprints
     */
    public Set<ResponseFingerprint> getAllResponseFingerprints() {
        Set<ResponseFingerprint> responseSet = new HashSet<>();
        for (VectorContainer vectorContainer : vectorContainerList) {
            responseSet.addAll(vectorContainer.getResponseFingerprintList());
        }
        return responseSet;
    }

    private List<ResponseCounter> getAllResponseCounters() {
        List<ResponseFingerprint> fingerprintList = new LinkedList<>();
        for (VectorContainer container : vectorContainerList) {
            fingerprintList.addAll(container.getResponseFingerprintList());
        }

        VectorContainer container = new VectorContainer(null, fingerprintList);
        return container.getDistinctResponsesCounterList();
    }

    /**
     * Retrieves the most common response across all vectors.
     *
     * @return The response counter with the highest occurrence count
     */
    public ResponseCounter retrieveMostCommonAnswer() {
        ResponseCounter defaultAnswer = null;
        for (ResponseCounter counter : getAllResponseCounters()) {
            if (defaultAnswer == null) {
                defaultAnswer = counter;
            } else if (defaultAnswer.getCounter() < counter.getCounter()) {
                defaultAnswer = counter;
            }
        }
        return defaultAnswer;
    }

    /**
     * Extends this test by adding additional vector responses. If a response is for an existing
     * vector, it is added to that vector's container; otherwise, a new container is created.
     *
     * @param vectorResponseList List of vector responses to add
     */
    public void extendTestWithVectorResponses(List<VectorResponse> vectorResponseList) {
        for (VectorResponse vectorResponse : vectorResponseList) {
            VectorContainer correctContainer = null;
            for (VectorContainer thisContainer : this.vectorContainerList) {
                if (thisContainer.getVector().equals(vectorResponse.getVector())) {
                    correctContainer = thisContainer;
                }
            }
            if (correctContainer != null) {
                correctContainer.addResponseFingerprint(vectorResponse.getFingerprint());
            } else {
                List<ResponseFingerprint> fingerprintList = new LinkedList<>();
                fingerprintList.add(vectorResponse.getFingerprint());
                vectorContainerList.add(
                        new VectorContainer(vectorResponse.getVector(), fingerprintList));
            }
        }
        updateInternals();
    }

    /**
     * Extends this test by merging in additional vector containers. If a container is for an
     * existing vector, the responses are merged; otherwise, the container is added as-is.
     *
     * @param vectorContainerList List of vector containers to merge
     */
    public void extendTestWithVectorContainers(List<VectorContainer> vectorContainerList) {
        for (VectorContainer otherContainer : vectorContainerList) {
            VectorContainer correctContainer = null;
            for (VectorContainer thisContainer : this.vectorContainerList) {
                if (thisContainer.getVector().equals(otherContainer.getVector())) {
                    correctContainer = thisContainer;
                }
            }
            if (correctContainer != null) {
                correctContainer.addResponseFingerprint(
                        otherContainer.getResponseFingerprintList());
            } else {
                this.vectorContainerList.add(otherContainer);
            }
        }
        updateInternals();
    }

    /**
     * Checks for equality errors between response fingerprints in this test.
     *
     * @return The first equality error found, or NONE if all fingerprints are properly comparable
     */
    public EqualityError getEqualityError() {
        Set<ResponseFingerprint> fingerPrintSet = getAllResponseFingerprints();
        for (ResponseFingerprint fingerprint1 : fingerPrintSet) {
            for (ResponseFingerprint fingerprint2 : fingerPrintSet) {
                EqualityError equalityError =
                        FingerprintChecker.checkEquality(fingerprint1, fingerprint2);
                if (equalityError != EqualityError.NONE) {
                    return equalityError;
                }
            }
        }
        return EqualityError.NONE;
    }

    /**
     * Updates internal state by recomputing the p-value and determining if there are distinct and
     * significant differences in responses.
     */
    protected final void updateInternals() {
        valueP = computePValue();
        distinctAnswers = getAllResponseFingerprints().size() > 1;
        this.significantDistinctAnswers = valueP < P_VALUE_SIGNIFICANCE_BORDER;
    }

    private double computePValue() {
        if (isFisherExactUsable()) {
            LOGGER.debug("Computing P value based on fisher's exact test");
            double fisher = computePValueFisherExact();
            return fisher;
        } else {
            LOGGER.debug("Computing P value based on Chi² test");
            return computePValueChiSquared();
        }
    }

    /**
     * Computes the p-value using Fisher's exact test.
     *
     * @return The computed p-value
     */
    abstract double computePValueFisherExact();

    /**
     * Computes the p-value using the Chi-squared test.
     *
     * @return The computed p-value
     */
    abstract double computePValueChiSquared();

    /**
     * Determines whether Fisher's exact test is applicable for the current data.
     *
     * @return true if Fisher's exact test can be used, false otherwise
     */
    abstract boolean isFisherExactUsable();
}
