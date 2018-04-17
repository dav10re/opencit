package com.intel.mtwilson.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.validation.ObjectModel;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import com.intel.mtwilson.imameasurement.xml.*;
import com.intel.dcsg.cpg.xml.JAXB;
import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.slf4j.LoggerFactory;

//import org.codehaus.jackson.annotate.JsonValue;

/**
 * Represents an ordered list of ima measurements.
 * 
 * These modules are stored as XML itself during the whitelisting process in the 
 * mw_ima_measurement_xml table.
 * 
 * During policy evaluation, this XML would be converted this XmlImaMeasurementLog for verifying
 * all the measurements of the individual modules using the XmlImaMeasurementLogEquals and
 * XmlImaMeasurementLogIntegrity policies.
 * 
 */
public class XmlImaMeasurementLog extends ObjectModel {
   
    private org.slf4j.Logger log = LoggerFactory.getLogger(getClass());
    private final PcrIndex pcrIndex;
    private final List<Measurement> measurements = new ArrayList<>();

    public XmlImaMeasurementLog(PcrIndex pcrIndex) {
        this.pcrIndex = pcrIndex;
    }
    
    @JsonCreator
    public XmlImaMeasurementLog(@JsonProperty("pcr_index") PcrIndex pcrIndex, @JsonProperty("xml_ima_measurement_log") String xmlImaMeasurementLog) {
        log.debug("XmlImaMeasurementLog Constructor: About to parse {} for PCR {}", xmlImaMeasurementLog, pcrIndex.toString());
        this.pcrIndex = pcrIndex;
        parseXmlImaMeasurementLog(xmlImaMeasurementLog);
        log.debug("XmlImaMeasurementLog Constructor: Parsed with output {}.", xmlImaMeasurementLog);
    }
    
    private void parseXmlImaMeasurementLog(String xmlImaMeasurements) {
        
        JAXB measurementLogJaxb = new JAXB();        
        if (xmlImaMeasurements != null && !xmlImaMeasurements.isEmpty()) {
            try {
                IMAMeasurements imameasurements = measurementLogJaxb.read(xmlImaMeasurements, IMAMeasurements.class);
                if (imameasurements.getImameasurements().size() > 0) {
                    for (MeasurementType measurementLogEntry : imameasurements.getImameasurements()) {
                        if (measurementLogEntry.getClass().equals(FileMeasurementType.class)) {
                            FileMeasurementType fileEntry = (FileMeasurementType) measurementLogEntry;
                            log.debug("File details {} - {}", fileEntry.getPath(), fileEntry.getValue());

                            HashMap<String,String> moduleInfo = new HashMap<>();
                            moduleInfo.put("Type", FileMeasurementType.class.getSimpleName());
                            
                            Measurement newFileModule = new MeasurementSha1(Sha1Digest.valueOfHex(fileEntry.getValue()), fileEntry.getPath(), moduleInfo);
                            this.measurements.add(newFileModule);
                        } else {
                            log.warn("Cannot cast measurement with class [{}] to any known CIT measurement type", measurementLogEntry.getClass().getSimpleName());
                            if (measurementLogEntry.getValue() != null && measurementLogEntry.getPath() != null) {
                                log.warn("Uncastable measurement has value [{}] and path [{}]", measurementLogEntry.getValue(), measurementLogEntry.getPath());
                                }
                        }
                    }
                }
                
            } catch (    IOException | JAXBException | XMLStreamException ex) {
                Logger.getLogger(XmlImaMeasurementLog.class.getName()).log(Level.SEVERE, null, ex);
            }
        }        
    }
    
    public PcrIndex getPcrIndex() { return pcrIndex; }
    public List<Measurement> getMeasurements() { return measurements; }
    
    /**
     * Checks to see if the PcrModuleManifest contains the given Measurement (value & description)
     * @param measurement
     * @return true if the PcrModuleManifest contains the given Measurement value
     */
    public boolean contains(Measurement m) {
        if( m == null ) { return false; }
        return measurements.contains(m); 
    }
    
    /**
     * Checks to see if the PcrModuleManifest contains a Measurement with the given SHA1 digest value
     * @param value
     * @return true if the PcrModuleManifest contains an entry with the specified value, false otherwise
     */
    public boolean contains(Sha1Digest value) {
        if( value == null ) { return false; }
        for(Measurement m : measurements) {
            if( m.getValue().equals(value) ) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Returns a string representing the PCR manifest, one PCR index-value pair
     * per line. Only non-null PCRs are represented in the output. 
     * 
     * @see java.lang.Object#toString()
     */
//    @JsonValue
    @Override
    public String toString() {
        String result = String.format("PCR %d module manifest:", pcrIndex.toInteger());
        for(Measurement m : measurements) {
            result = result.concat(m.getValue().toString()+" "+m.getLabel()+"\n");
        }
        return result;
    }
    
    @Override
    public int hashCode() {
        HashCodeBuilder builder = new HashCodeBuilder(17,57);
        builder.append(pcrIndex);
        for(Measurement m : measurements) {
            builder.append(m);
        }
        return builder.toHashCode(); 
    }
    
    /**
     * A PCR Manifest is equal to another if it contains exactly the same
     * digest values in the same registers. In addition, because a PCR Manifest
     * can have ignored (null) digests for some registers, both manifests must
     * have null digests for the same registers.
     * @param other
     * @return 
     */
    @Override
    public boolean equals(Object other) {
        if( other == null ) { return false; }
        if( other == this ) { return true; }
        if( other.getClass() != this.getClass() ) { return false; }
        XmlImaMeasurementLog rhs = (XmlImaMeasurementLog)other;
//        EqualsBuilder builder = new EqualsBuilder(); // org.apache.commons.lang3.builder.EqualsBuilder
        if( !pcrIndex.equals(rhs.pcrIndex)) { return false; }
        if( !measurements.equals(rhs.measurements)) { return false; }
        return true;
    }

    @Override
    public void validate() {
        if( measurements == null ) {
            fault("Measurement set is null");
        }
        else if( measurements.isEmpty() ) {
            fault("Measurement set is empty");
        }
        else {
            for(Measurement m : measurements) {
                if( !m.isValid() ) {
                    fault(m, "Invalid measurement %s in module manifest", m.getLabel());
                }
            }
        }
    }

    
}
