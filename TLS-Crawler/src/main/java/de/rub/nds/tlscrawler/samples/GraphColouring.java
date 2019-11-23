/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.samples;

import org.jgrapht.UndirectedGraph;
import org.jgrapht.alg.ChromaticNumber;

/**
 *
 */
public class GraphColouring {

    private GraphColouring() {
    }

    public static int getColouringNumber(UndirectedGraph graph) {
        int findGreedyChromaticNumber = ChromaticNumber.findGreedyChromaticNumber(graph);
        return findGreedyChromaticNumber;
    }

}
