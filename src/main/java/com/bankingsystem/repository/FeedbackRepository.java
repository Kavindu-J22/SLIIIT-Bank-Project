// src/main/java/com/bankingsystem/repository/FeedbackRepository.java
package com.bankingsystem.repository;

import com.bankingsystem.model.Feedback;
import com.bankingsystem.model.FeedbackStatus;
import com.bankingsystem.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FeedbackRepository extends JpaRepository<Feedback, Long> {
    List<Feedback> findByCustomer(User customer);
    List<Feedback> findByStatus(FeedbackStatus status);
}