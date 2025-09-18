// src/main/java/com/bankingsystem/BankingSystemApplication.java
package com.bankingsystem;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.bankingsystem.model.User;
import com.bankingsystem.model.Role;
import com.bankingsystem.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class BankingSystemApplication {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final Logger logger = LoggerFactory.getLogger(BankingSystemApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(BankingSystemApplication.class, args);
    }

    @PostConstruct
    public void initDefaultAdmin() {
        if (userRepository.findByUsername("admin").isEmpty()) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("adminpass"));
            admin.setRole(Role.ADMIN);
            userRepository.save(admin);
            logger.info("Default admin created: username 'admin', password 'adminpass'");
        }
    }
}