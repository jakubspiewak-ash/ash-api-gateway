package com.jakubspiewak.ashapigateway.service;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SecurePathValidator {

  // TODO: improve this or use Spring Security and secure methods usage as well
  private static final List<String> openApiEndpoints = List.of("/auth", "/user/register");

  boolean isSecured(ServerHttpRequest request) {
    // TODO: wtf: "contains" xd
    return openApiEndpoints.stream().noneMatch(request.getURI().getPath()::contains);
  }
}
