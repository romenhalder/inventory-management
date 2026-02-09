package com.romen.inventory.controller;

import com.romen.inventory.dto.*;
import com.romen.inventory.entity.OtpLog;
import com.romen.inventory.entity.User;
import com.romen.inventory.service.AuthService;
import com.romen.inventory.service.EmailService;
import com.romen.inventory.service.OtpService;
import com.romen.inventory.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final OtpService otpService;
    private final EmailService emailService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        AuthResponse response = authService.authenticate(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
        User user = userService.registerUser(request);

        AuthResponse response = AuthResponse.builder()
                .email(user.getEmail())
                .phone(user.getPhone())
                .fullName(user.getFullName())
                .role(user.getRole())
                .userId(user.getId())
                .isEmailVerified(user.getIsEmailVerified())
                .isPhoneVerified(user.getIsPhoneVerified())
                .message("Registration successful. Please verify your email.")
                .build();

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/send-otp")
    public ResponseEntity<Map<String, String>> sendOtp(@RequestBody SendOtpRequest request) {
        String identifier = request.getIdentifier();
        boolean isEmail = identifier.contains("@");

        OtpLog.OtpType otpType = OtpLog.OtpType.valueOf(request.getOtpType().toUpperCase());

        OtpLog otpLog;
        if (isEmail) {
            otpLog = otpService.createOtp(identifier, null, otpType);
            emailService.sendOtpEmail(identifier, otpLog.getOtp(), otpType.name());
        } else {
            otpLog = otpService.createOtp(null, identifier, otpType);
        }

        Map<String, String> response = new HashMap<>();
        response.put("message", "OTP sent successfully");
        response.put("identifier", identifier);
        response.put("otpType", otpType.name());
        response.put("otp", "123456"); // For testing

        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestBody VerifyRequest request) {
        User user = userService.verifyEmail(request.getIdentifier(), request.getOtp());

        Map<String, String> response = new HashMap<>();
        response.put("message", "Email verified successfully");
        response.put("email", user.getEmail());
        response.put("userId", user.getId().toString());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@RequestBody ResetPasswordRequest request) {
        userService.resetPassword(request.getIdentifier(), request.getOtp(), request.getNewPassword());

        Map<String, String> response = new HashMap<>();
        response.put("message", "Password reset successful");
        response.put("identifier", request.getIdentifier());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/test")
    public ResponseEntity<Map<String, String>> test() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Auth API is working!");
        return ResponseEntity.ok(response);
    }
}