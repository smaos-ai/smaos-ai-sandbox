package com.sovereignnexus.smaos.guard;

import java.io.IOException;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

/**
 * Enterprise Spring Boot / WebClient Remediation Filter (Moat 1 & DORA Art. 17)
 * Hard boundary invariant: Evidence Absent => UNKNOWN
 * Prevents Spring AI / LangChain4j harnesses from returning ungrounded confirmation.
 *
 * Catches both SocketTimeoutException (HTTP 504) and IOException (TCP RST /
 * ConnectException) to cover all transport-layer fault modes.
 */
public class ProofOrStopFilter implements ExchangeFilterFunction {

    /**
     * Thrown when the wire provides no confirmation but the agent attempted to
     * claim a settled state. Forces callers to treat the transaction as UNKNOWN.
     */
    public static class AgentDiscrepancyException extends RuntimeException {
        public AgentDiscrepancyException(String message) {
            super(message);
        }
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        return next.exchange(request)
            .onErrorResume(java.net.SocketTimeoutException.class, ex ->
                Mono.error(new AgentDiscrepancyException(
                    "DORA Art. 17 Violation: HTTP 504 timeout — wire dropped with no settlement receipt. "
                    + "State forced to UNKNOWN."
                ))
            )
            .onErrorResume(IOException.class, ex ->
                Mono.error(new AgentDiscrepancyException(
                    "DORA Art. 17 Violation: Transport-layer abort (TCP RST / ConnectException) — "
                    + "no settlement receipt. State forced to UNKNOWN."
                ))
            );
    }
}
