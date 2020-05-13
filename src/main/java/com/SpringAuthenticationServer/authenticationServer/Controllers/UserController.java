package com.SpringAuthenticationServer.authenticationServer.Controllers;

import com.SpringAuthenticationServer.authenticationServer.DataLayer.ApplicationUserRepository;
import com.SpringAuthenticationServer.authenticationServer.Models.ApplicationUser;
import com.SpringAuthenticationServer.authenticationServer.Models.Role;
import com.SpringAuthenticationServer.authenticationServer.Models.Subject;
import com.auth0.jwt.JWT;
import com.google.gson.Gson;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

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
        Role userRole = new Role(0,"ROLE_ADMIN");
        user.setRoles(new HashSet<>(Arrays.asList(userRole)));
        user = applicationUserRepository.save(user);


        ApplicationUser guest = new ApplicationUser();
        guest.setUsername(user.getUsername() + "guest");
        guest.setPassword(bCryptPasswordEncoder.encode("password"));
        guest.setMainUser(user);
        Role guestRole = new Role(1,"ROLE_USER");
        guest.setRoles(new HashSet<>(Arrays.asList(guestRole)));


        //making the jwt code for the guest without limit!
        Gson gson = new Gson();
        String token = JWT.create()
                .withSubject(gson.toJson( new Subject(guest.getUsername(),guest.getRoles())))
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(SECRET.getBytes()));
        guest.setToken(token);


        applicationUserRepository.save(guest);

    }

    @GetMapping("/getGuestToken")
    public String generateToken(Principal principal){
        return applicationUserRepository.findByMainUserId(applicationUserRepository.findByUsername(principal.getName()).getId()).getToken();
    }

   // @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/OK")
    public String OK(Principal principal){
        return principal.getName();
    }



    //@PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/OKSecured")
    public String OKSec(Principal principal){
        return principal.getName();
    }

    @GetMapping("/findMe")
    public String findMe(Principal principal){
        return ((Role)applicationUserRepository.findByUsername(principal.getName()).getRoles().toArray()[0]).getRoleName();
    }


}
