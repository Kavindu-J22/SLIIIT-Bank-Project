// src/main/java/com/bankingsystem/controller/LoanController.java
package com.bankingsystem.controller;

import com.bankingsystem.model.Loan;
import com.bankingsystem.model.LoanStatus;
import com.bankingsystem.model.Role;
import com.bankingsystem.model.User;
import com.bankingsystem.service.LoanService;
import com.bankingsystem.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/loan")
public class LoanController {

    @Autowired
    private LoanService loanService;

    @Autowired
    private UserService userService;

    @GetMapping("/list")
    public String list(Model model, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        List<Loan> loans;
        if (currentUser.getRole() == Role.CUSTOMER) {
            loans = loanService.findByApplicant(currentUser);
        } else {
            loans = loanService.findAll();
        }
        model.addAttribute("loans", loans);
        return "loan-list";
    }

    @GetMapping("/apply")
    public String applyForm(Model model) {
        model.addAttribute("loan", new Loan());
        return "loan-apply";
    }

    @PostMapping("/apply")
    public String apply(@Valid @ModelAttribute Loan loan, BindingResult bindingResult, Authentication authentication) {
        if (bindingResult.hasErrors()) {
            return "loan-apply";
        }
        User currentUser = getCurrentUser(authentication);
        loanService.applyLoan(loan, currentUser);
        return "redirect:/loan/list";
    }

    @GetMapping("/review/{id}")
    public String reviewForm(@PathVariable Long id, Model model, Authentication authentication) {
        Loan loan = loanService.findById(id).orElseThrow(() -> new RuntimeException("Loan not found"));
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() != Role.STAFF && currentUser.getRole() != Role.ADMIN) return "error";
        model.addAttribute("loan", loan);
        return "loan-review";
    }

    @PostMapping("/review/{id}")
    public String review(@PathVariable Long id, @ModelAttribute Loan loan, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        loanService.reviewLoan(id, currentUser, LoanStatus.IN_REVIEW);
        return "redirect:/loan/list";
    }

    @GetMapping("/approve/{id}")
    public String approve(@PathVariable Long id, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() != Role.ADMIN) return "error";
        loanService.updateStatus(id, currentUser, LoanStatus.APPROVED);
        return "redirect:/loan/list";
    }

    @GetMapping("/reject/{id}")
    public String reject(@PathVariable Long id, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() != Role.ADMIN) return "error";
        loanService.updateStatus(id, currentUser, LoanStatus.REJECTED);
        return "redirect:/loan/list";
    }

    @GetMapping("/delete/{id}")
    public String delete(@PathVariable Long id, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() != Role.ADMIN) return "error";
        loanService.deleteById(id);
        return "redirect:/loan/list";
    }

    private User getCurrentUser(Authentication authentication) {
        String username = authentication.getName();
        return userService.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
    }
}