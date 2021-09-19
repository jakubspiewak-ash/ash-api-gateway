package com.jakubspiewak.ashapigateway.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.UUID;

@FeignClient("ash-auth-service")
public interface AuthService {
    @GetMapping("/validate/{token}")
    Boolean isTokenValid(@PathVariable String token);

    @GetMapping("/id/{token}")
    UUID resolveToken(@PathVariable String token);

}
