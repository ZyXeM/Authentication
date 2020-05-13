package com.SpringAuthenticationServer.authenticationServer.Models;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class Subject implements Serializable {
    private  String username;



    private HashSet<String> grantedAuthorities;

    public Subject(String username, Set<Role> roles) {
        this.username = username;
        grantedAuthorities = new HashSet<>();
        for(Role role : roles){
            grantedAuthorities.add(role.getRoleName());
        }
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }



    public Subject() {
    }

    public Subject(String username, HashSet<String> grantedAuthorities) {
        this.username = username;
        this.grantedAuthorities = grantedAuthorities;
    }

    public HashSet<String> getGrantedAuthorities() {
        return grantedAuthorities;
    }

    public void setGrantedAuthorities(HashSet<String> grantedAuthorities) {
        this.grantedAuthorities = grantedAuthorities;
    }

    public Collection<GrantedAuthority> convertToAuthorities(){
        HashSet<GrantedAuthority> set = new HashSet<>();
        for (String auth: grantedAuthorities) {
            set.add(new SimpleGrantedAuthority(auth));
        }
        return set;
    }
}
