/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.as.rest.v2.repository;

import com.intel.dcsg.cpg.io.UUID;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.My;
import com.intel.mtwilson.as.controller.TblModuleManifestJpaController;
import com.intel.mtwilson.as.data.TblModuleManifest;
import com.intel.mtwilson.as.rest.v2.model.MleModule;
import com.intel.mtwilson.as.rest.v2.model.MleModuleCollection;
import com.intel.mtwilson.as.rest.v2.model.MleModuleFilterCriteria;
import com.intel.mtwilson.as.rest.v2.model.MleModuleLocator;
import com.intel.mtwilson.i18n.ErrorCode;
import com.intel.mtwilson.datatypes.ModuleWhiteList;
import com.intel.mtwilson.jaxrs2.server.resource.DocumentRepository;
import com.intel.mtwilson.wlm.business.MleBO;
import java.util.List;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author ssbangal
 */
public class MleModuleRepository implements DocumentRepository<MleModule, MleModuleCollection, MleModuleFilterCriteria, MleModuleLocator> {

    private Logger log = LoggerFactory.getLogger(getClass().getName());
    
    @Override
    @RequiresPermissions("mle_modules:search")    
    public MleModuleCollection search(MleModuleFilterCriteria criteria) {
        MleModuleCollection objCollection = new MleModuleCollection();
        try {
            TblModuleManifestJpaController jpaController = My.jpa().mwModuleManifest();
            if (criteria.mleUuid != null) {
                List<TblModuleManifest> objList = jpaController.findTblModuleManifestByMleUuid(criteria.mleUuid.toString());
                if (objList != null && !objList.isEmpty()) {                    
                    // Before we add to the collection we need to check if the user has specified any other search criteria
                    if (criteria.id != null) {
                        for(TblModuleManifest obj : objList) {
                            if (obj.getUuid_hex().contains(criteria.id.toString()))
                                objCollection.getMleModules().add(convert(obj));
                        }                        
                    } else if (criteria.nameContains != null && !criteria.nameContains.isEmpty()) {
                        for(TblModuleManifest obj : objList) {
                            if (obj.getComponentName().contains(criteria.nameContains))
                                objCollection.getMleModules().add(convert(obj));
                        }
                    } else if (criteria.valueEqualTo != null && !criteria.valueEqualTo.isEmpty()) {
                        for(TblModuleManifest obj : objList) {
                            if (obj.getDigestValue().equalsIgnoreCase(criteria.valueEqualTo))
                                objCollection.getMleModules().add(convert(obj));
                        }                        
                    } else {
                        for(TblModuleManifest obj : objList) {
                            objCollection.getMleModules().add(convert(obj));
                        }
                    }
                }                
            }
        } catch (ASException aex) {
            throw aex;            
        } catch (Exception ex) {
            log.error("Error during Module whitelist search.", ex);
            throw new ASException(ErrorCode.WS_MODULE_WHITELIST_RETRIEVAL_ERROR, ex.getClass().getSimpleName());
        }
        return objCollection;
    }

    @Override
    @RequiresPermissions("mle_modules:retrieve")    
    public MleModule retrieve(MleModuleLocator locator) {
        if( locator.moduleUuid == null ) { return null; }
        try {
            TblModuleManifestJpaController jpaController = My.jpa().mwModuleManifest();
            TblModuleManifest obj = jpaController.findTblModuleManifestByUuid(locator.moduleUuid.toString());
            if (obj != null) {
                MleModule convObj = convert(obj);
                return convObj;
            }
        } catch (ASException aex) {
            throw aex;            
        } catch (Exception ex) {
            log.error("Error during Module whitelist retrieval.", ex);
            throw new ASException(ErrorCode.WS_MODULE_WHITELIST_RETRIEVAL_ERROR, ex.getClass().getSimpleName());
        }
        return null;
    }

    @Override
    @RequiresPermissions("mle_modules:store")    
    public void store(MleModule item) {
        ModuleWhiteList obj = new ModuleWhiteList();
        try {
            obj.setDigestValue(item.getModuleValue());
            obj.setDescription(item.getDescription());
            new MleBO().updateModuleWhiteList(obj, null, item.getId().toString());
        } catch (ASException aex) {
            throw aex;            
        } catch (Exception ex) {
            log.error("Error during module whitelist update.", ex);
            throw new ASException(ErrorCode.WS_MODULE_WHITELIST_UPDATE_ERROR, ex.getClass().getSimpleName());
        }        
    }

    @Override
    @RequiresPermissions("mle_modules:create")    
    public void create(MleModule item) {
        ModuleWhiteList obj = new ModuleWhiteList();
        try {
            obj.setComponentName(item.getModuleName());
            obj.setDigestValue(item.getModuleValue());
            obj.setDescription(item.getDescription());
            obj.setEventName(item.getEventName());
            obj.setExtendedToPCR(item.getExtendedToPCR());
            obj.setPackageName(item.getPackageName());
            obj.setPackageVendor(item.getPackageVendor());
            obj.setPackageVersion(item.getPackageVersion());
            obj.setUseHostSpecificDigest(item.getUseHostSpecificDigest());
            new MleBO().addModuleWhiteList(obj, null, item.getId().toString(), item.getMleUuid());
        } catch (ASException aex) {
            throw aex;            
        } catch (Exception ex) {
            log.error("Error during module whitelist creation.", ex);
            throw new ASException(ErrorCode.WS_MODULE_WHITELIST_CREATE_ERROR, ex.getClass().getSimpleName());
        }        
    }

    @Override
    @RequiresPermissions("mle_modules:delete")    
    public void delete(MleModuleLocator locator) {
        if (locator.moduleUuid == null) { return; }
        try {
            new MleBO().deleteModuleWhiteList(null, null, null, null, null, null, null, locator.moduleUuid.toString());
        } catch (ASException aex) {
            throw aex;            
        } catch (Exception ex) {
            log.error("Error during module whitelist deletion.", ex);
            throw new ASException(ErrorCode.WS_MODULE_WHITELIST_DELETE_ERROR, ex.getClass().getSimpleName());
        }        
    }
    
    private MleModule convert(TblModuleManifest obj) {
        MleModule convObj = new MleModule();
        convObj.setId(UUID.valueOf(obj.getUuid_hex()));
        convObj.setMleUuid(obj.getUuid_hex());
        convObj.setModuleName(obj.getComponentName());
        convObj.setDescription(obj.getDescription());
        convObj.setModuleValue(obj.getDigestValue());
        convObj.setEventName(obj.getEventID().getName());
        convObj.setExtendedToPCR(obj.getExtendedToPCR());
        convObj.setPackageName(obj.getPackageName());
        convObj.setPackageVendor(obj.getPackageVendor());
        convObj.setPackageVersion(obj.getPackageVersion());
        return convObj;
    }

    @Override
    @RequiresPermissions("mle_modules:delete,search")    
    public void delete(MleModuleFilterCriteria criteria) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
