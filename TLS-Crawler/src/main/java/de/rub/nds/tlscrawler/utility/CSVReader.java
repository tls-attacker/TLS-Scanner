package de.rub.nds.tlscrawler.utility;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class CSVReader {

    private static Logger LOG = LoggerFactory.getLogger(CSVReader.class);
    BufferedReader csvReader;

    public CSVReader(String name) {
        try {
            csvReader = new BufferedReader(new FileReader(name));
        } catch(Exception e) {
            System.out.println("Uups! Exception");
            e.printStackTrace();
        }
    }

    public List<String> readCSV() {
        try {
            String row; // csvReader.readLine();
            List<String> domains = new ArrayList<String>();
            while ((row = csvReader.readLine()) != null) {
                String[] data = row.split(",");
                domains.add(data[0].replaceAll("\"", ""));
            }

            csvReader.close();
            return domains;
        } catch (IOException e) {
            LOG.error("Failed to read data from the csv file");
            return null;
        }

    }



}

