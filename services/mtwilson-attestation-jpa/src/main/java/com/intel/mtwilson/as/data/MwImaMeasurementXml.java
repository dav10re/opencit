package com.intel.mtwilson.as.data;

import java.io.Serializable;
import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author dav10re
 */
@Entity
@Table(name = "mw_ima_measurement_xml")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "MwImaMeasurementXml.findAll", query = "SELECT m FROM MwImaMeasurementXml m"),
    @NamedQuery(name = "MwImaMeasurementXml.findById", query = "SELECT m FROM MwImaMeasurementXml m WHERE m.id = :id"),
    @NamedQuery(name = "MwImaMeasurementXml.findByMleID", query = "SELECT m FROM MwImaMeasurementXml m WHERE m.mleId.id =:mleId"),
    @NamedQuery(name = "MwImaMeasurementXml.findByContent", query = "SELECT m FROM MwImaMeasurementXml m WHERE m.content = :content")})
public class MwImaMeasurementXml implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @Basic(optional = false)
    @Column(name = "id")
    private String id;
    @JoinColumn(name = "mleId", referencedColumnName = "id")
    @ManyToOne(optional = false)
    private TblMle mleId;    
    @Column(name = "content")
    private String content;

    public MwImaMeasurementXml() {
    }

    public MwImaMeasurementXml(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public TblMle getMleId() {
        return mleId;
    }

    public void setMleId(TblMle mleId) {
        this.mleId = mleId;
    }
    
    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (id != null ? id.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof MwImaMeasurementXml)) {
            return false;
        }
        MwImaMeasurementXml other = (MwImaMeasurementXml) object;
        if ((this.id == null && other.id != null) || (this.id != null && !this.id.equals(other.id))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "com.intel.mtwilson.as.data.MwImaMeasurementXml[ id=" + id + " ]";
    }
    
}
