package com.homework.xacml;

public class XACMLRequest {
    String role;
    String resource;
    String action;

    public XACMLRequest(String role, String resource, String action) {
        this.role = role;
        this.resource = resource;
        this.action = action;
    }
    
}
