package com.homework.xacml;

import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.attr.StringAttribute;

import com.sun.xacml.ctx.Attribute;
import com.sun.xacml.ctx.RequestCtx;
import com.sun.xacml.ctx.Subject;

import java.net.URI;
import java.net.URISyntaxException;

import java.util.HashSet;
import java.util.Set;
/*
     * Sets up the Subject section of the request. This Request only has
     * one Subject section, and it uses the default category. To create a
     * Subject with a different category, you simply specify the category
     * when you construct the Subject object.
     *
     * @return a Set of Subject instances for inclusion in a Request
     *
     * @throws URISyntaxException if there is a problem with a URI
 *
     */


public class RequestBuilder
{

  static final String ACTION_IDENTIFIER = "urn:oasis:names:tc:xacml:1.0:action:action-id";
  //static final String RESOURCE_IDENTIFIER = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
  static final String SUBJECT_IDENTIFIER = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
  //static final String SUBJECT_ROLE_IDENTIFIER = "urn:oasis:names:tc:xacml:2.0:subject:role";
  static final String SUBJECT_ROLE_IDENTIFIER = "role";



    public static Set<Subject> setupSubjects(String role) throws URISyntaxException {
        HashSet<Attribute> attributes = new HashSet<Attribute>();
        HashSet<Subject> subjects = new HashSet<Subject>();

        if(role==null)
            subjects=null;
        else
        {
            attributes.add(new Attribute(new URI(SUBJECT_ROLE_IDENTIFIER),
                                        null, null,
                                        new StringAttribute(role)));
            subjects.add(new Subject(attributes));
        }

        return subjects;
    }


    /**
     * Creates a Resource specifying the resource-id, a required attribute.
     *
     * @return a Set of Attributes for inclusion in a Request
     *
     * @throws URISyntaxException if there is a problem with a URI
     */
    public static Set<Attribute> setupResource(String res) throws URISyntaxException {
        HashSet<Attribute> resource = new HashSet<Attribute>();

        // the resource being requested : è una URI ma passata come stringa
        StringAttribute value = new StringAttribute("http://localhost:1200" + res);

        // create the resource using a standard, required identifier for
        // the resource being requested
        resource.add(new Attribute(new URI(EvaluationCtx.RESOURCE_ID),
                                   null, null, value));

        return resource;
    }

    /**
     * Creates an Action specifying the action-id, an optional attribute.
     *
     * @return a Set of Attributes for inclusion in a Request
     *
     * @throws URISyntaxException if there is a problem with a URI
     */
    public static Set<Attribute> setupAction(String act) throws URISyntaxException {
        HashSet<Attribute> action = new HashSet<Attribute>();

        // this is a standard URI that can optionally be used to specify
        // the action being requested
        URI actionId = new URI(ACTION_IDENTIFIER);

        // create the action
        action.add(new Attribute(actionId, null, null, new StringAttribute(act)));

        return action;
    }


    public static RequestCtx createXACMLRequest(String role, String resource, String action) throws Exception{

      RequestCtx XACMLrequest = new RequestCtx(setupSubjects(role), setupResource(resource), setupAction(action), new HashSet<>());

      return XACMLrequest;
    }

}
