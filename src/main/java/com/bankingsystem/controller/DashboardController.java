package com.bankingsystem.controller;

import com.bankingsystem.model.Role;
import com.bankingsystem.model.User;
import com.bankingsystem.repository.*;
import com.bankingsystem.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private static final Logger logger = LoggerFactory.getLogger(DashboardController.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private TransactionRepository transactionRepository;

    @Autowired
    private LoanRepository loanRepository;

    @Autowired
    private FeedbackRepository feedbackRepository;

    @Autowired
    private UserService userService;

    @GetMapping("/dashboard")
    public String dashboard(Model model, Authentication authentication) {
        logger.info("Dashboard accessed - Authenticated: {}", authentication.isAuthenticated());
        logger.info("Username from auth: {}", authentication.getName());

        String username = authentication.getName();
        User currentUser = userService.findByUsername(username).orElse(null);
        if (currentUser == null) {
            logger.error("User not found in DB for username: {}", username);
            return "customer-dashboard"; // Safe default
        }

        Role role = currentUser.getRole();
        logger.info("User role: {}", role);

        if (role == Role.CUSTOMER) {
            model.addAttribute("userCount", userRepository.count());
            model.addAttribute("accountCount", accountRepository.count());
            model.addAttribute("transactionCount", transactionRepository.count());
            model.addAttribute("loanCount", loanRepository.count());
            model.addAttribute("feedbackCount", feedbackRepository.count());
            return "Customer-dashboard";
        } else if (role == Role.STAFF) {
            return "staff-dashboard";
        } else {
            return "admin-dashboard";
        }
    }
}