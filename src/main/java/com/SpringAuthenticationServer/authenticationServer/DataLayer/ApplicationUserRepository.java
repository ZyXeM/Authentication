package com.SpringAuthenticationServer.authenticationServer.DataLayer;

import com.SpringAuthenticationServer.authenticationServer.Models.ApplicationUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApplicationUserRepository extends JpaRepository<ApplicationUser,Long> {
    ApplicationUser findByUsername(String username);
    ApplicationUser findByMainUserId(long MainUserId);
}
