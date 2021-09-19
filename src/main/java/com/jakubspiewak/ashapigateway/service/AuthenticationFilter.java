package com.jakubspiewak.ashapigateway.service;

import com.jakubspiewak.ashapigateway.feign.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static java.util.Objects.requireNonNull;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Component
@RefreshScope
@RequiredArgsConstructor
public class AuthenticationFilter implements GatewayFilter {

  private final String AUTHORIZATION_HEADER_NAME = "Authorization";

  private final AuthService authService;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    final var request = exchange.getRequest();

    if (!hasAuthorizationHeader(request)) {
      return onError(exchange, UNAUTHORIZED);
    }

    final var token = getAuthorizationHeader(request);

    if (!authService.isTokenValid(token)) {
      return onError(exchange, HttpStatus.FORBIDDEN);
    }

    populateRequestWithHeaders(exchange, token);

    return chain.filter(exchange);
  }

  private boolean hasAuthorizationHeader(ServerHttpRequest request) {
    return request.getHeaders().containsKey(AUTHORIZATION_HEADER_NAME);
  }

  private String getAuthorizationHeader(ServerHttpRequest request) {
    return requireNonNull(request.getHeaders().get(AUTHORIZATION_HEADER_NAME)).get(0);
  }

  private void populateRequestWithHeaders(ServerWebExchange exchange, String token) {
    final var userId = authService.resolveToken(token);

    exchange.getRequest().mutate().header("ash-user-id", String.valueOf(userId)).build();
  }

  private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
    final var response = exchange.getResponse();
    response.setStatusCode(httpStatus);
    return response.setComplete();
  }
}
