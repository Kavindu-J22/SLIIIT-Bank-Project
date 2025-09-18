// src/main/java/com/bankingsystem/controller/FeedbackController.java
package com.bankingsystem.controller;

import com.bankingsystem.model.Feedback;
import com.bankingsystem.model.FeedbackStatus;
import com.bankingsystem.model.Role;
import com.bankingsystem.model.User;
import com.bankingsystem.service.FeedbackService;
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
@RequestMapping("/feedback")
public class FeedbackController {

    @Autowired
    private FeedbackService feedbackService;

    @Autowired
    private UserService userService;

    @GetMapping("/list")
    public String list(Model model, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        List<Feedback> feedbacks;
        if (currentUser.getRole() == Role.CUSTOMER) {
            feedbacks = feedbackService.findByCustomer(currentUser);
        } else {
            feedbacks = feedbackService.findAll();
        }
        model.addAttribute("feedbacks", feedbacks);
        return "feedback-list";
    }

    @GetMapping("/submit")
    public String submitForm(Model model, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() != Role.CUSTOMER) return "error";
        model.addAttribute("feedback", new Feedback());
        return "feedback-submit";
    }

    @PostMapping("/submit")
    public String submit(@Valid @ModelAttribute Feedback feedback, BindingResult bindingResult, Authentication authentication) {
        if (bindingResult.hasErrors()) {
            return "feedback-submit";
        }
        User currentUser = getCurrentUser(authentication);
        feedbackService.submitFeedback(feedback, currentUser);
        return "redirect:/feedback/list";
    }

    @GetMapping("/update/{id}")
    public String updateForm(@PathVariable Long id, Model model, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() != Role.STAFF && currentUser.getRole() != Role.ADMIN) return "error";
        Feedback feedback = feedbackService.findById(id).orElseThrow(() -> new RuntimeException("Feedback not found"));
        model.addAttribute("feedback", feedback);
        model.addAttribute("statuses", FeedbackStatus.values());
        return "feedback-update";
    }

    @PostMapping("/update/{id}")
    public String update(@PathVariable Long id, @RequestParam String reply, @RequestParam FeedbackStatus status, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        feedbackService.updateFeedback(id, reply, status, currentUser);
        return "redirect:/feedback/list";
    }

    @GetMapping("/delete/{id}")
    public String delete(@PathVariable Long id, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() != Role.ADMIN) return "error";
        feedbackService.deleteById(id);
        return "redirect:/feedback/list";
    }

    private User getCurrentUser(Authentication authentication) {
        String username = authentication.getName();
        return userService.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
    }
}