package com.jakubspiewak.ashapigateway.service;

import com.jakubspiewak.ashapimodellib.model.auth.ApiTokenInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Optional.ofNullable;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Slf4j
@Component
@RefreshScope
@RequiredArgsConstructor
public class AuthenticationFilter implements GlobalFilter {

  // TODO: improvemnt:
  // there should be a better option
  // maybe make some kind of lib or util class in
  // other repo
  private static final String AUTH_SERVICE_ENDPOINT = "lb://ash-auth-service/auth";
  private static final String AUTHORIZATION_HEADER_NAME = "Authorization";
  private static final String ASH_USER_ID_HEADER_NAME = "ash-user-id";

  private final WebClient webClient;
  private final SecurePathValidator securePathValidator;

  private static ApiTokenInfo createNonAcceptedTokenInfo() {
    return ApiTokenInfo.builder().isAccepted(false).build();
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    final var request = exchange.getRequest();

    if (securePathValidator.isSecured(request)) {
      final var token = getAuthorizationHeaderValue(request);

      if (token.isEmpty()) {
        return onError(exchange, UNAUTHORIZED, "Authorization header is missing");
      }

      return getApiTokenInfo(token.get())
          .filter(ApiTokenInfo::getIsAccepted)
          .switchIfEmpty(Mono.error(new RuntimeException("Token is invalid")))
          .map(populateHeader(exchange))
          .flatMap(chain::filter)
          .onErrorResume(throwable -> onError(exchange, FORBIDDEN, throwable.getMessage()));
    }
    return chain.filter(exchange);
  }

  private Function<ApiTokenInfo, ServerWebExchange> populateHeader(ServerWebExchange exchange) {
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
        .bodyToMono(ApiTokenInfo.class)
        .onErrorReturn(createNonAcceptedTokenInfo());
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

  private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus, String message) {
    final var response = exchange.getResponse();
    final var messageBytes = message.getBytes(UTF_8);
    final var buffer = response.bufferFactory().wrap(messageBytes);

    response.setStatusCode(httpStatus);
    return response.writeWith(Mono.just(buffer));
  }
}
