package com.bing.lan.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

    @RequestMapping("/hello")
    public String hello() {
        return "hello security";
    }

    @RequestMapping("/denyAll")
    public String denyAll() {
        return "denyAll 拒绝所有访问";
    }

    @RequestMapping("/anonymous")
    public String anonymous() {
        return "anonymous 只允许匿名访问";
    }

    @RequestMapping("/admin/hello")
    public String admin() {
        return "admin 角色可以访问";
    }

    @RequestMapping("/user/hello")
    public String user() {
        return "user 角色可以访问";
    }
}