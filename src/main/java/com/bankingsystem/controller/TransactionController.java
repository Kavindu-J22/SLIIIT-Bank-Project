// src/main/java/com/bankingsystem/controller/TransactionController.java
package com.bankingsystem.controller;

import com.bankingsystem.model.Account;
import com.bankingsystem.model.Role;
import com.bankingsystem.model.Transaction;
import com.bankingsystem.model.User;
import com.bankingsystem.service.AccountService;
import com.bankingsystem.service.TransactionService;
import com.bankingsystem.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/transaction")
public class TransactionController {

    @Autowired
    private TransactionService transactionService;

    @Autowired
    private AccountService accountService;

    @Autowired
    private UserService userService;

    @Autowired
    private HttpSession session;

    @GetMapping("/deposit/{accountId}")
    public String depositForm(@PathVariable Long accountId, Model model, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        Account account = accountService.findById(accountId).orElseThrow();
        if (!account.getUser().equals(currentUser))
            return "error";
        model.addAttribute("account", account);
        return "transaction-deposit";
    }

    @PostMapping("/deposit")
    public String deposit(@RequestParam Long accountId, @RequestParam double amount) {
        transactionService.deposit(accountId, amount);
        return "redirect:/account/view/" + accountId;
    }

    @GetMapping("/withdraw/{accountId}")
    public String withdrawForm(@PathVariable Long accountId, Model model, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        Account account = accountService.findById(accountId).orElseThrow();
        if (!account.getUser().equals(currentUser))
            return "error";
        model.addAttribute("account", account);
        return "transaction-withdraw";
    }

    @PostMapping("/withdraw")
    public String withdraw(@RequestParam Long accountId, @RequestParam double amount) {
        transactionService.withdraw(accountId, amount);
        return "redirect:/account/view/" + accountId;
    }

    @GetMapping("/transfer/{fromAccountId}")
    public String transferForm(@PathVariable Long fromAccountId, Model model, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        Account fromAccount = accountService.findById(fromAccountId).orElseThrow();
        if (!fromAccount.getUser().equals(currentUser))
            return "error";
        model.addAttribute("fromAccount", fromAccount);
        return "transaction-transfer";
    }

    @PostMapping("/transfer/initiate")
    public String initiateTransfer(@RequestParam Long fromAccountId, @RequestParam String toAccountNumber,
            @RequestParam double amount) {
        Account toAccount = accountService.findByAccountNumber(toAccountNumber)
                .orElseThrow(() -> new RuntimeException("To account not found"));
        String otp = String.format("%06d", (int) (Math.random() * 1000000));
        session.setAttribute("transferOtp", otp);
        session.setAttribute("transferFromId", fromAccountId);
        session.setAttribute("transferToId", toAccount.getId());
        session.setAttribute("transferAmount", amount);
        System.out.println("Generated OTP for transfer: " + otp); // Simulate sending OTP
        return "transaction-otp";
    }

    @PostMapping("/transfer/verify")
    public String verifyTransfer(@RequestParam String otp, Model model) {
        String storedOtp = (String) session.getAttribute("transferOtp");
        if (storedOtp != null && storedOtp.equals(otp)) {
            Long fromId = (Long) session.getAttribute("transferFromId");
            Long toId = (Long) session.getAttribute("transferToId");
            double amount = (double) session.getAttribute("transferAmount");
            transactionService.transfer(fromId, toId, amount);
            clearTransferSession();
            return "redirect:/transaction/history";
        } else {
            model.addAttribute("error", "Invalid OTP");
            return "transaction-otp";
        }
    }

    private void clearTransferSession() {
        session.removeAttribute("transferOtp");
        session.removeAttribute("transferFromId");
        session.removeAttribute("transferToId");
        session.removeAttribute("transferAmount");
    }

    @GetMapping("/history")
    public String history(Model model, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        List<Account> accounts = accountService.findByUser(currentUser);
        if (accounts.isEmpty()) {
            // If user has no accounts, show empty transaction list with a message
            model.addAttribute("transactions", List.of());
            model.addAttribute("noAccountsMessage", "You don't have any accounts yet. Please create an account first.");
            return "transaction-history";
        }
        Account account = accounts.get(0); // Assume one account per user
        List<Transaction> transactions = transactionService.getTransactionsForAccount(account);
        model.addAttribute("transactions", transactions);
        return "transaction-history";
    }

    @GetMapping("/export/csv")
    public ResponseEntity<String> exportCsv(Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        List<Account> accounts = accountService.findByUser(currentUser);
        if (accounts.isEmpty())
            throw new RuntimeException("No account found");
        Account account = accounts.get(0);
        List<Transaction> transactions = transactionService.getTransactionsForAccount(account);
        String csv = transactionService.exportToCSV(transactions);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=transactions.csv")
                .contentType(MediaType.TEXT_PLAIN)
                .body(csv);
    }

    @GetMapping("/reverse/{id}")
    public String reverse(@PathVariable Long id, Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        if (currentUser.getRole() != Role.ADMIN)
            return "error";
        transactionService.reverseTransaction(id);
        return "redirect:/transaction/history";
    }

    private User getCurrentUser(Authentication authentication) {
        String username = authentication.getName();
        return userService.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
    }
}