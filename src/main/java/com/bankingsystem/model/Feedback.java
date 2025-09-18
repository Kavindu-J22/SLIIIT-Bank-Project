// src/main/java/com/bankingsystem/model/Feedback.java
package com.bankingsystem.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;

@Entity
public class Feedback {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Subject is required")
    private String subject;

    @NotBlank(message = "Message is required")
    private String message;

    @Enumerated(EnumType.STRING)
    private FeedbackStatus status;

    private String reply;

    @ManyToOne
    private User customer;

    @ManyToOne
    private User staff;

    // Default constructor
    public Feedback() {
    }

    // Constructor with all fields
    public Feedback(Long id, String subject, String message, FeedbackStatus status,
            String reply, User customer, User staff) {
        this.id = id;
        this.subject = subject;
        this.message = message;
        this.status = status;
        this.reply = reply;
        this.customer = customer;
        this.staff = staff;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public FeedbackStatus getStatus() {
        return status;
    }

    public void setStatus(FeedbackStatus status) {
        this.status = status;
    }

    public String getReply() {
        return reply;
    }

    public void setReply(String reply) {
        this.reply = reply;
    }

    public User getCustomer() {
        return customer;
    }

    public void setCustomer(User customer) {
        this.customer = customer;
    }

    public User getStaff() {
        return staff;
    }

    public void setStaff(User staff) {
        this.staff = staff;
    }
}