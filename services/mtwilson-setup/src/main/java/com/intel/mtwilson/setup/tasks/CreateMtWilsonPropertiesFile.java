/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.setup.tasks;

import com.intel.dcsg.cpg.io.Platform;
import com.intel.dcsg.cpg.validation.ObjectModel;
import com.intel.mtwilson.My;
import com.intel.mtwilson.setup.AbstractSetupTask;
import com.intel.mtwilson.setup.ConfigurationException;
import com.intel.mtwilson.setup.LocalSetupTask;
import com.intel.mtwilson.setup.SetupTask;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.apache.commons.io.IOUtils;

/**
 * Depends on ConfigureFilesystem. 
 * TODO this really shouldn't be its own task, the setup application should
 * create a PropertiesConfiguration object, pass it to all the setup tasks,
 * and then store it at the end to mtwilson.properties
 *
 * @author jbuhacoff
 */
public class CreateMtWilsonPropertiesFile extends LocalSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(CreateMtWilsonPropertiesFile.class);
    private String mtwilsonConf; // optional input
    private transient File mtwilsonProperties; // not an input;  path relative to mtwilsonConf is hard-coded 

    @Override
    protected void configure() throws Exception {
        mtwilsonConf = My.filesystem().getConfigurationPath(); //My.configuration().getMtWilsonConf();
        if (mtwilsonConf == null) {
            configuration("MTWILSON_CONF is not configured");
        }
        // we don't store MTWILSON_CONF in the configuration because it's needed to load the configuration itself
    }

    @Override
    protected void validate() throws Exception {
        mtwilsonProperties = new File(mtwilsonConf + File.separator + "mtwilson.properties");
        checkFileExists("MTWILSON_CONF", mtwilsonConf);
        checkFileExists("mtwilson.properties", mtwilsonProperties.getAbsolutePath());
    }

    @Override
    protected void execute() throws Exception {
        FileOutputStream out = new FileOutputStream(mtwilsonProperties);
//        getConfiguration().
        Properties properties = new Properties();
        properties.store(out, "automatically generated");
        out.close();
    }

}
