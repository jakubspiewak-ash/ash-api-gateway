package com.jakubspiewak.ashapigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.openfeign.EnableFeignClients;

@EnableFeignClients
@EnableEurekaClient
@SpringBootApplication
public class AshApiGatewayApplication {
  public static void main(String[] args) {
    SpringApplication.run(AshApiGatewayApplication.class, args);
  }
}
