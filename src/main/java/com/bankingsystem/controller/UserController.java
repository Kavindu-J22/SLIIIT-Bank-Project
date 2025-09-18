// src/main/java/com/bankingsystem/controller/UserController.java
package com.bankingsystem.controller;

import com.bankingsystem.model.Role;
import com.bankingsystem.model.User;
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
@RequestMapping("/admin/user")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/list")
    public String list(@RequestParam(required = false) String search, Model model, Authentication authentication) {
        if (getCurrentUser(authentication).getRole() != Role.ADMIN) return "error";
        List<User> users;
        if (search != null && !search.isBlank()) {
            users = userService.searchByUsername(search);
        } else {
            users = userService.findAll();
        }
        model.addAttribute("users", users);
        return "user-list";
    }

    @GetMapping("/create")
    public String createForm(Model model, Authentication authentication) {
        if (getCurrentUser(authentication).getRole() != Role.ADMIN) return "error";
        model.addAttribute("user", new User());
        model.addAttribute("roles", Role.values());
        return "user-create";
    }

    @PostMapping("/create")
    public String create(@Valid @ModelAttribute User user, BindingResult bindingResult, Model model, Authentication authentication) {
        if (getCurrentUser(authentication).getRole() != Role.ADMIN) return "error";
        if (bindingResult.hasErrors()) {
            model.addAttribute("roles", Role.values());
            return "user-create";
        }
        userService.saveUser(user);
        return "redirect:/admin/user/list";
    }

    @GetMapping("/edit/{id}")
    public String editForm(@PathVariable Long id, Model model, Authentication authentication) {
        if (getCurrentUser(authentication).getRole() != Role.ADMIN) return "error";
        User user = userService.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        model.addAttribute("user", user);
        model.addAttribute("roles", Role.values());
        return "user-edit";
    }

    @PostMapping("/edit/{id}")
    public String edit(@PathVariable Long id, @ModelAttribute User user, Authentication authentication) {
        if (getCurrentUser(authentication).getRole() != Role.ADMIN) return "error";
        user.setId(id);
        userService.updateUser(user);
        return "redirect:/admin/user/list";
    }

    @GetMapping("/delete/{id}")
    public String delete(@PathVariable Long id, Authentication authentication) {
        if (getCurrentUser(authentication).getRole() != Role.ADMIN) return "error";
        userService.deleteById(id);
        return "redirect:/admin/user/list";
    }

    private User getCurrentUser(Authentication authentication) {
        String username = authentication.getName();
        return userService.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
    }
}