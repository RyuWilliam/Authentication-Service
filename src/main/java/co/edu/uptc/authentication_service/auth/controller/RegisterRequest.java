package co.edu.uptc.authentication_service.auth.controller;

public record RegisterRequest(
        String name,
        String email,
        String password
) {
}