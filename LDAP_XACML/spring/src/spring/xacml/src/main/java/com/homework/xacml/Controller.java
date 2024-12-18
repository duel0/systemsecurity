package com.homework.xacml;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class Controller {

  @PostMapping("/xacml")
  Integer evaluate(@RequestBody XACMLRequest request) {
        try
        {
            return new AuthFilter().doFilter(request.role, request.resource, request.action);
        }
        catch(Exception e)
        {
            System.err.println(e.getMessage());
            System.err.println(e.getStackTrace());
            return -1;
        }
    }

}
