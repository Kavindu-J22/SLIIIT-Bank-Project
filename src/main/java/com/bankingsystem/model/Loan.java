// src/main/java/com/bankingsystem/model/Loan.java
package com.bankingsystem.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

@Entity
public class Loan {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Loan type is required")
    private String loanType;

    @Positive(message = "Amount must be positive")
    private double amount;

    @Positive(message = "Duration must be positive")
    private int duration;

    @Enumerated(EnumType.STRING)
    private LoanStatus status;

    @ManyToOne
    private User applicant;

    @ManyToOne
    private User reviewer;

    @ManyToOne
    private User approver;

    // Default constructor
    public Loan() {
    }

    // Constructor with all fields
    public Loan(Long id, String loanType, double amount, int duration, LoanStatus status,
            User applicant, User reviewer, User approver) {
        this.id = id;
        this.loanType = loanType;
        this.amount = amount;
        this.duration = duration;
        this.status = status;
        this.applicant = applicant;
        this.reviewer = reviewer;
        this.approver = approver;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getLoanType() {
        return loanType;
    }

    public void setLoanType(String loanType) {
        this.loanType = loanType;
    }

    public double getAmount() {
        return amount;
    }

    public void setAmount(double amount) {
        this.amount = amount;
    }

    public int getDuration() {
        return duration;
    }

    public void setDuration(int duration) {
        this.duration = duration;
    }

    public LoanStatus getStatus() {
        return status;
    }

    public void setStatus(LoanStatus status) {
        this.status = status;
    }

    public User getApplicant() {
        return applicant;
    }

    public void setApplicant(User applicant) {
        this.applicant = applicant;
    }

    public User getReviewer() {
        return reviewer;
    }

    public void setReviewer(User reviewer) {
        this.reviewer = reviewer;
    }

    public User getApprover() {
        return approver;
    }

    public void setApprover(User approver) {
        this.approver = approver;
    }
}