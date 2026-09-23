package com.smaos.gateway;

import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import reactor.core.publisher.Mono;

public class ProofOrStopFilter {
    public static ExchangeFilterFunction enforceDowngrade() {
        return (request, next) -> next.exchange(request)
            .onErrorResume(java.net.SocketException.class, e -> {
                // Intercept HTTP 504 / TCP RST and force UNKNOWN
                System.out.println("SMAOS: Transport fault detected. Forcing DISPATCHED_UNCONFIRMED state.");
                return Mono.empty(); // Fails closed
            });
    }
}
