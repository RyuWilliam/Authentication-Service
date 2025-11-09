package co.edu.uptc.authentication_service.auth.controller;


public record AuthRequest(
        String email,
        String password
) {
}