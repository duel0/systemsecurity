package com.homework.xacml;

import java.io.File;
import java.io.IOException;
import java.util.*;

import com.sun.xacml.PDP;
import com.sun.xacml.PDPConfig;
import com.sun.xacml.ctx.RequestCtx;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Result;
import com.sun.xacml.finder.AttributeFinder;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.impl.CurrentEnvModule;
import com.sun.xacml.finder.impl.FilePolicyModule;


/**
 * Servlet Filter implementation class AuthFilter
 */
public class AuthFilter {
	File[] listaFile;//contiene le policy disponibili

    /**
     * Default constructor.
     */
    public AuthFilter() {
    }

	/**
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	public Integer doFilter(String role, String resource, String action) throws IOException
	{
		File f;
        String policyfile;
        FilePolicyModule policyModule = new FilePolicyModule();
        PolicyFinder policyFinder = new PolicyFinder();
        Set<FilePolicyModule> policyModules = new HashSet<>();

        // Setting the path of the policy folder
        String PATH_POLICY = "/app/policy";

        System.out.println("PATH_POLICY: " + PATH_POLICY);

        listaFile = (new File(PATH_POLICY)).listFiles();

        for(int i=0;i<listaFile.length;i++)
        {
                f=listaFile[i];
                policyfile = f.getAbsolutePath();
                policyModule.addPolicy(policyfile); //aggiunge solo il nome del file
                policyModules.add(policyModule);
                policyFinder.setModules(policyModules);
        }

        CurrentEnvModule envModule = new CurrentEnvModule();
        AttributeFinder attrFinder = new AttributeFinder();
        List<CurrentEnvModule> attrModules = new ArrayList<>();
        attrModules.add(envModule);
        attrFinder.setModules(attrModules);


        try {
            RequestCtx XACMLrequest = RequestBuilder.createXACMLRequest(role, resource, action);


            PDP pdp = new PDP(new PDPConfig(attrFinder, policyFinder, null));

            ResponseCtx XACMLresponse = pdp.evaluate(XACMLrequest);

            Set ris_set = XACMLresponse.getResults();
            Result ris = null;
            Iterator it = ris_set.iterator();

            while (it.hasNext()) {
                ris = (Result) it.next();
            }
            int dec = ris.getDecision();

            if (dec == 0) { //permit
                return 0;
            } else if (dec == 1) { //deny
                return 1;
            } else if (dec == 2||dec==3) { //not applicable o indeterminate
                return 2;
            }
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }

        return -1;

	}

}
