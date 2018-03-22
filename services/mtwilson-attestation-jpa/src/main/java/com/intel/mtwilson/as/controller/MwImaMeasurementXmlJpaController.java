package com.intel.mtwilson.as.controller;

import com.intel.mtwilson.as.controller.exceptions.NonexistentEntityException;
import com.intel.mtwilson.as.controller.exceptions.PreexistingEntityException;
import com.intel.mtwilson.as.data.MwImaMeasurementXml;
import com.intel.mtwilson.as.data.MwMleSource;
import java.io.Serializable;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Query;
import javax.persistence.EntityNotFoundException;
import javax.persistence.NoResultException;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import org.eclipse.persistence.config.CacheUsage;
import org.eclipse.persistence.config.HintValues;
import org.eclipse.persistence.config.QueryHints;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author dav10re
 */
public class MwImaMeasurementXmlJpaController implements Serializable {
    private Logger log = LoggerFactory.getLogger(getClass());
    
    public MwImaMeasurementXmlJpaController(EntityManagerFactory emf) {
        this.emf = emf;
    }
    private EntityManagerFactory emf = null;

    public EntityManager getEntityManager() {
        return emf.createEntityManager();
    }

    public void create(MwImaMeasurementXml mwImaMeasurementXml) throws PreexistingEntityException, Exception {
        EntityManager em = getEntityManager();
        try {
            em.getTransaction().begin();
            em.persist(mwImaMeasurementXml);
            em.getTransaction().commit();
        } catch (Exception ex) {
            if (findMwImaMeasurementXml(mwImaMeasurementXml.getId()) != null) {
                throw new PreexistingEntityException("MwImaMeasurementXml " + mwImaMeasurementXml + " already exists.", ex);
            }
            throw ex;
        } finally {
            em.close();
        }
    }

    public void edit(MwImaMeasurementXml mwImaMeasurementXml) throws NonexistentEntityException, Exception {
        EntityManager em = getEntityManager();
        try {            
            em.getTransaction().begin();
            em.merge(mwImaMeasurementXml);
            em.getTransaction().commit();
        } catch (Exception ex) {
            String msg = ex.getLocalizedMessage();
            if (msg == null || msg.length() == 0) {
                String id = mwImaMeasurementXml.getId();
                if (findMwImaMeasurementXml(id) == null) {
                    throw new NonexistentEntityException("The mwImaMeasurementXml with id " + id + " no longer exists.");
                }
            }
            throw ex;
        } finally {
            em.close();
        }
    }

    public void destroy(String id) throws NonexistentEntityException {
        EntityManager em = getEntityManager();
        try {            
            em.getTransaction().begin();
            MwImaMeasurementXml mwImaMeasurementXml;
            try {
                mwImaMeasurementXml = em.getReference(MwImaMeasurementXml.class, id);
                mwImaMeasurementXml.getId();
            } catch (EntityNotFoundException enfe) {
                throw new NonexistentEntityException("The mwImaMeasurementXml with id " + id + " no longer exists.", enfe);
            }
            em.remove(mwImaMeasurementXml);
            em.getTransaction().commit();
        } finally {
            em.close();
        }
    }

    public List<MwImaMeasurementXml> findMwImaMeasurementXmlEntities() {
        return findMwImaMeasurementXmlEntities(true, -1, -1);
    }

    public List<MwImaMeasurementXml> findMwImaMeasurementXmlEntities(int maxResults, int firstResult) {
        return findMwImaMeasurementXmlEntities(false, maxResults, firstResult);
    }

    private List<MwImaMeasurementXml> findMwImaMeasurementXmlEntities(boolean all, int maxResults, int firstResult) {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            cq.select(cq.from(MwImaMeasurementXml.class));
            Query q = em.createQuery(cq);
            if (!all) {
                q.setMaxResults(maxResults);
                q.setFirstResult(firstResult);
            }
            return q.getResultList();
        } finally {
            em.close();
        }
    }

    public MwImaMeasurementXml findMwImaMeasurementXml(String id) {
        EntityManager em = getEntityManager();
        try {
            return em.find(MwImaMeasurementXml.class, id);
        } finally {
            em.close();
        }
    }

    public int getMwImaMeasurementXmlCount() {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            Root<MwImaMeasurementXml> rt = cq.from(MwImaMeasurementXml.class);
            cq.select(em.getCriteriaBuilder().count(rt));
            Query q = em.createQuery(cq);
            return ((Long) q.getSingleResult()).intValue();
        } finally {
            em.close();
        }
    }

    /**
     * Retrieves the Measurement XML for the specified MLE if it exists.
     * @param id
     * @return 
     */
    public MwImaMeasurementXml findByMleId(Integer id) {
        
        EntityManager em = getEntityManager();
        try {

            Query query = em.createNamedQuery("MwImaMeasurementXml.findByMleID");
            query.setParameter("mleId", id);

            query.setHint(QueryHints.REFRESH, HintValues.TRUE);
            query.setHint(QueryHints.CACHE_USAGE, CacheUsage.DoNotCheckCache);

            MwImaMeasurementXml imaMeasurementXml = (MwImaMeasurementXml) query.getSingleResult();
            return imaMeasurementXml;

        } catch(NoResultException e){
        	log.error(String.format("MLE information with identity %d not found in the DB.", id));
        	return null;
        } finally {
            em.close();
        }               
    }    
    
}
