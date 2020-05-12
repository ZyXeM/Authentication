package com.SpringAuthenticationServer.authenticationServer.Controllers;

import com.SpringAuthenticationServer.authenticationServer.DataLayer.ApplicationUserRepository;
import com.SpringAuthenticationServer.authenticationServer.Models.ApplicationUser;
import com.auth0.jwt.JWT;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Date;

import static com.SpringAuthenticationServer.authenticationServer.Security.SecurityConstants.*;
import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

@RestController
@RequestMapping("/users")
public class UserController {
    private ApplicationUserRepository applicationUserRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserController(ApplicationUserRepository applicationUserRepository,
                          BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.applicationUserRepository = applicationUserRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @PostMapping("/sign-up")
    public void signUp(@RequestBody ApplicationUser user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user = applicationUserRepository.save(user);


        ApplicationUser guest = new ApplicationUser();
        guest.setUsername(user.getUsername() + "guest");
        guest.setPassword(bCryptPasswordEncoder.encode("password"));
        guest.setMainUser(user);

        //making the jwt code for the guest without limit!
        String token = JWT.create()
                .withSubject( guest.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(SECRET.getBytes()));
        guest.setToken(token);
        applicationUserRepository.save(guest);

    }

    @GetMapping("/getGuestToken")
    public String generateToken(Principal principal){
        return applicationUserRepository.findByMainUserId(applicationUserRepository.findByUsername(principal.getName()).getId()).getToken();
    }

    @GetMapping("/OK")
    public String OK(Principal principal){
        return principal.getName();
    }

}
