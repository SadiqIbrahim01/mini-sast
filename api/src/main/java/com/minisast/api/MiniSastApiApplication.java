package com.minisast.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot entry point for the Mini SAST REST API.
 *
 * Phase 7 will add:
 *   - POST /api/v1/scan        — trigger a scan
 *   - GET  /api/v1/results/{id} — retrieve scan result
 *   - Authentication (API keys)
 *   - Rate limiting
 *   - Async scan execution
 */
@SpringBootApplication
public class MiniSastApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(MiniSastApiApplication.class, args);
    }
}