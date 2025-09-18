// src/main/java/com/bankingsystem/service/FeedbackService.java
package com.bankingsystem.service;

import com.bankingsystem.model.Feedback;
import com.bankingsystem.model.FeedbackStatus;
import com.bankingsystem.model.User;
import com.bankingsystem.repository.FeedbackRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class FeedbackService {

    @Autowired
    private FeedbackRepository feedbackRepository;

    public Feedback submitFeedback(Feedback feedback, User customer) {
        feedback.setCustomer(customer);
        feedback.setStatus(FeedbackStatus.OPEN);
        return feedbackRepository.save(feedback);
    }

    public void updateFeedback(Long id, String reply, FeedbackStatus status, User staff) {
        Feedback feedback = feedbackRepository.findById(id).orElseThrow(() -> new RuntimeException("Feedback not found"));
        feedback.setReply(reply);
        feedback.setStatus(status);
        feedback.setStaff(staff);
        feedbackRepository.save(feedback);
    }

    public List<Feedback> findAll() {
        return feedbackRepository.findAll();
    }

    public Optional<Feedback> findById(Long id) {
        return feedbackRepository.findById(id);
    }

    public List<Feedback> findByCustomer(User customer) {
        return feedbackRepository.findByCustomer(customer);
    }

    public void deleteById(Long id) {
        feedbackRepository.deleteById(id);
    }
}