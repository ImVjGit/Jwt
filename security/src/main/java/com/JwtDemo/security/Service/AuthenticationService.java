package com.JwtDemo.security.Service;

import com.JwtDemo.security.request.AuthenticationRequest;
import com.JwtDemo.security.request.RegisterRequest;
import com.JwtDemo.security.entity.Repository.UserRepository;
import com.JwtDemo.security.entity.Role;
import com.JwtDemo.security.entity.User;
import com.JwtDemo.security.response.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    @Autowired
    private final UserRepository userRepository;
    @Autowired
    private  final PasswordEncoder passwordEncoder;
    @Autowired
    private  final JwtService jwtservice;
    @Autowired
    private  final AuthenticationManager authenticationManager;


    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
         userRepository.save(user);
        var jwtToken= jwtservice.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow(()->new UsernameNotFoundException("User not found"));
        var jwtToken= jwtservice.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();

    }
}
