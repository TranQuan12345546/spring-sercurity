package com.example.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {
    @GetMapping("/")
    public String home() {
        return "index";
    }


    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_SALE') ")
    @GetMapping("/dashboard")
    public String getDashboard() {
        return "dashboard";
    }

    @PreAuthorize("hasAnyRole('ROLE_ADMIN') ")
    @GetMapping("/users")
    public String getUser() {
        return "user";
    }

    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_SALE') ")
    @GetMapping("/product")
    public String getProduct() {
        return "product";
    }
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_SALE', 'ROLE_AUTHOR') ")
    @GetMapping("/blog")
    public String getBlog() {
        return "blog";
    }
    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/user-info")
    public String getUserInfo() {
        return "user-info";
    }
}
