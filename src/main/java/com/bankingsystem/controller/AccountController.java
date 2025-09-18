// src/main/java/com/bankingsystem/controller/AccountController.java
package com.bankingsystem.controller;

import com.bankingsystem.model.Account;
import com.bankingsystem.model.AccountType;
import com.bankingsystem.model.Role;
import com.bankingsystem.model.User;
import com.bankingsystem.service.AccountService;
import com.bankingsystem.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/account")
public class AccountController {

    @Autowired
    private AccountService accountService;

    @Autowired
    private UserService userService;

    @GetMapping("/list")
    public String listAccounts(Model model, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() == Role.ADMIN) {
            model.addAttribute("accounts", accountService.findAll());
        } else {
            model.addAttribute("accounts", accountService.findByUser(currentUser));
        }
        return "account-list";
    }

    @GetMapping("/create")
    public String createForm(Model model) {
        model.addAttribute("account", new Account());
        model.addAttribute("accountTypes", AccountType.values());
        return "account-create";
    }

    @PostMapping("/create")
    public String create(@Valid @ModelAttribute Account account, BindingResult bindingResult, Authentication authentication) {
        if (bindingResult.hasErrors()) {
            return "account-create";
        }
        User currentUser = getCurrentUser(authentication);
        accountService.createAccount(account, currentUser.getId());
        return "redirect:/account/list";
    }

    @GetMapping("/edit/{id}")
    public String editForm(@PathVariable Long id, Model model, Authentication authentication) {
        Account account = accountService.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() != Role.ADMIN && !account.getUser().equals(currentUser)) {
            return "error";
        }
        model.addAttribute("account", account);
        model.addAttribute("accountTypes", AccountType.values());
        return "account-edit";
    }

    @PostMapping("/edit/{id}")
    public String edit(@PathVariable Long id, @Valid @ModelAttribute Account account, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "account-edit";
        }
        account.setId(id);
        Account existing = accountService.findById(id).orElseThrow();
        account.setAccountNumber(existing.getAccountNumber());
        account.setUser(existing.getUser());
        accountService.updateAccount(account);
        return "redirect:/account/list";
    }

    @GetMapping("/delete/{id}")
    public String delete(@PathVariable Long id, Authentication authentication) {
        Account account = accountService.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() != Role.ADMIN && !account.getUser().equals(currentUser)) {
            return "error";
        }
        accountService.deleteById(id);
        return "redirect:/account/list";
    }

    @GetMapping("/view/{id}")
    public String view(@PathVariable Long id, Model model, Authentication authentication) {
        Account account = accountService.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() != Role.ADMIN && !account.getUser().equals(currentUser)) {
            return "error";
        }
        model.addAttribute("account", account);
        return "account-view";
    }

    private User getCurrentUser(Authentication authentication) {
        String username = authentication.getName();
        return userService.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
    }
}