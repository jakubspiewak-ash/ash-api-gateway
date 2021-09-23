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

import java.util.Collections;
import java.util.Optional;
import java.util.function.Function;

import static java.util.Optional.ofNullable;
import static java.util.function.Predicate.not;
import static org.springframework.http.HttpStatus.*;

@Component
@RefreshScope
@RequiredArgsConstructor
public class AuthenticationFilter implements GlobalFilter {

  private static final String AUTH_SERVICE_ENDPOINT = "lb://ash-auth-service/auth";
  private static final String AUTHORIZATION_HEADER_NAME = "Authorization";
  private static final String ASH_USER_ID_HEADER_NAME = "ash-user-id";

  private final WebClient webClient;
  private final SecurePathValidator securePathValidator;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    final var request = exchange.getRequest();

    if (securePathValidator.isSecured(request)) {
      final var token = getAuthorizationHeaderValue(request);

      if (token.isEmpty()) {
        return onError(exchange, UNAUTHORIZED);
      }

      return getApiTokenInfo(token.get())
          .filter(not(ApiTokenInfo::getIsExpired))
          .map(populateUserIdHeader(exchange))
          .flatMap(chain::filter)
          .switchIfEmpty(onError(exchange, FORBIDDEN));
    }
    return chain.filter(exchange);
  }

  private Function<ApiTokenInfo, ServerWebExchange> populateUserIdHeader(
      ServerWebExchange exchange) {
    return info -> {
      exchange
          .getRequest()
          .mutate()
          .header(ASH_USER_ID_HEADER_NAME, info.getUserId().toString())
          .build();
      return exchange;
    };
  }

  private Mono<ApiTokenInfo> getApiTokenInfo(String token) {
    return webClient
        .get()
        .uri(createGetTokenInfoEndpoint(token))
        .retrieve()
        .bodyToMono(ApiTokenInfo.class);
  }

  private String createGetTokenInfoEndpoint(String token) {
    return String.format("%s/%s", AUTH_SERVICE_ENDPOINT, token);
  }

  private Optional<String> getAuthorizationHeaderValue(ServerHttpRequest request) {
    return ofNullable(request.getHeaders().get(AUTHORIZATION_HEADER_NAME))
        .orElseGet(Collections::emptyList)
        .stream()
        .findFirst();
  }

  private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
    final var response = exchange.getResponse();
    response.setStatusCode(httpStatus);
    return response.setComplete();
  }
}
