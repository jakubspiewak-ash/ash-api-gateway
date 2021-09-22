package com.jakubspiewak.ashapigateway.service;

import com.jakubspiewak.ashapimodellib.model.auth.ApiTokenInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.function.Function;

import static java.util.Objects.requireNonNull;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Component
@RefreshScope
@RequiredArgsConstructor
public class AuthenticationFilter implements GlobalFilter {

  private static final String AUTH_SERVICE_ENDPOINT = "lb://ash-auth-service/auth";
  private static final String AUTHORIZATION_HEADER_NAME = "Authorization";

  private final WebClient webClient;
  private final SecurePathValidator securePathValidator;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    final var request = exchange.getRequest();

    if (securePathValidator.isSecured(request)) {
      if (!hasAuthorizationHeader(request)) {
        return onError(exchange, UNAUTHORIZED);
      }

      final var token = getAuthorizationHeader(request);
      return getApiTokenInfo(token).flatMap(handleToken(exchange, chain));
    }
    return chain.filter(exchange);
  }

  private Function<ApiTokenInfo, Mono<? extends Void>> handleToken(
      ServerWebExchange exchange, GatewayFilterChain chain) {
    return tokenInfo -> {
      if (tokenInfo.getIsExpired()) {
        return onError(exchange, FORBIDDEN);
      }
      populateRequestWithHeaders(exchange, tokenInfo);
      return chain.filter(exchange);
    };
  }

  private Mono<ApiTokenInfo> getApiTokenInfo(String token) {
    return webClient
        .get()
        .uri(String.format("%s/%s", AUTH_SERVICE_ENDPOINT, token))
        .retrieve()
        .bodyToMono(ApiTokenInfo.class);
  }

  private boolean hasAuthorizationHeader(ServerHttpRequest request) {
    return request.getHeaders().containsKey(AUTHORIZATION_HEADER_NAME);
  }

  private String getAuthorizationHeader(ServerHttpRequest request) {
    return requireNonNull(request.getHeaders().get(AUTHORIZATION_HEADER_NAME)).get(0);
  }

  private void populateRequestWithHeaders(ServerWebExchange exchange, ApiTokenInfo tokenInfo) {
    final var userId = tokenInfo.getUserId();

    exchange.getRequest().mutate().header("ash-user-id", String.valueOf(userId)).build();
  }

  private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
    final var response = exchange.getResponse();
    response.setStatusCode(httpStatus);
    return response.setComplete();
  }
}
