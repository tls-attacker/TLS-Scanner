/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.scans.IScan;

/**
 *
 * @author robert
 */
public interface IScanProvider {
    public IScan getCurrentScan();
}
