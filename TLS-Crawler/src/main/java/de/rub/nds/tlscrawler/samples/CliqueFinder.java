/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.samples;

import java.util.List;
import java.util.Set;
import org.jgrapht.Graph;
import org.jgrapht.UndirectedGraph;
import org.jgrapht.alg.BronKerboschCliqueFinder;

/**
 *
 */
public class CliqueFinder {

    private UndirectedGraph graph;

    public CliqueFinder(UndirectedGraph graph) {
        super();
        this.graph = graph;
    }

    public int getMaxCliqueSize() {
        BronKerboschCliqueFinder finder = new BronKerboschCliqueFinder(graph);
        return finder.getBiggestMaximalCliques().size();
//        
//        lazyRun();
//        int size = 0;
//        for (Set<String> clique : allMaximalCliques) {
//            if (clique.size() > size) {
//                size = clique.size();
//            }
//        }
//        System.out.println("Before:" + size);
//        lazyRun();
//        for (Set<String> clique : allMaximalCliques) {
//            if (clique.size() > size) {
//                size = clique.size();
//            }
//        }
//        System.out.println("After:" + size);
//
//        return allMaximalCliques;

    }

}
