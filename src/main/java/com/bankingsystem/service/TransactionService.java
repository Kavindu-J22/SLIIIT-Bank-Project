// src/main/java/com/bankingsystem/service/TransactionService.java
package com.bankingsystem.service;

import com.bankingsystem.model.Account;
import com.bankingsystem.model.Transaction;
import com.bankingsystem.model.TransactionType;
import com.bankingsystem.repository.AccountRepository;
import com.bankingsystem.repository.TransactionRepository;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class TransactionService {

    @Autowired
    private TransactionRepository transactionRepository;

    @Autowired
    private AccountRepository accountRepository;

    public void deposit(Long accountId, double amount) {
        if (amount <= 0) throw new RuntimeException("Amount must be positive");
        Account account = accountRepository.findById(accountId).orElseThrow(() -> new RuntimeException("Account not found"));
        account.setBalance(account.getBalance() + amount);
        accountRepository.save(account);

        Transaction transaction = new Transaction();
        transaction.setAmount(amount);
        transaction.setType(TransactionType.DEPOSIT);
        transaction.setDate(LocalDateTime.now());
        transaction.setToAccount(account);
        transaction.setDescription("Deposit");
        transactionRepository.save(transaction);
    }

    public void withdraw(Long accountId, double amount) {
        if (amount <= 0) throw new RuntimeException("Amount must be positive");
        Account account = accountRepository.findById(accountId).orElseThrow(() -> new RuntimeException("Account not found"));
        if (account.getBalance() < amount) throw new RuntimeException("Insufficient balance");
        account.setBalance(account.getBalance() - amount);
        accountRepository.save(account);

        Transaction transaction = new Transaction();
        transaction.setAmount(amount);
        transaction.setType(TransactionType.WITHDRAWAL);
        transaction.setDate(LocalDateTime.now());
        transaction.setFromAccount(account);
        transaction.setDescription("Withdrawal");
        transactionRepository.save(transaction);
    }

    public void transfer(Long fromAccountId, Long toAccountId, double amount) {
        if (amount <= 0) throw new RuntimeException("Amount must be positive");
        Account fromAccount = accountRepository.findById(fromAccountId).orElseThrow(() -> new RuntimeException("From account not found"));
        Account toAccount = accountRepository.findById(toAccountId).orElseThrow(() -> new RuntimeException("To account not found"));
        if (fromAccount.getBalance() < amount) throw new RuntimeException("Insufficient balance");

        fromAccount.setBalance(fromAccount.getBalance() - amount);
        toAccount.setBalance(toAccount.getBalance() + amount);
        accountRepository.save(fromAccount);
        accountRepository.save(toAccount);

        Transaction transaction = new Transaction();
        transaction.setAmount(amount);
        transaction.setType(TransactionType.TRANSFER);
        transaction.setDate(LocalDateTime.now());
        transaction.setFromAccount(fromAccount);
        transaction.setToAccount(toAccount);
        transaction.setDescription("Transfer from " + fromAccount.getAccountNumber() + " to " + toAccount.getAccountNumber());
        transactionRepository.save(transaction);
    }

    public List<Transaction> getTransactionsForAccount(Account account) {
        return transactionRepository.findByFromAccountOrToAccount(account, account);
    }

    public void reverseTransaction(Long transactionId) {
        Transaction transaction = transactionRepository.findById(transactionId).orElseThrow(() -> new RuntimeException("Transaction not found"));
        TransactionType type = transaction.getType();
        double amount = transaction.getAmount();

        if (type == TransactionType.DEPOSIT) {
            withdraw(transaction.getToAccount().getId(), amount);
        } else if (type == TransactionType.WITHDRAWAL) {
            deposit(transaction.getFromAccount().getId(), amount);
        } else if (type == TransactionType.TRANSFER) {
            transfer(transaction.getToAccount().getId(), transaction.getFromAccount().getId(), amount);
        }
    }

    public String exportToCSV(List<Transaction> transactions) {
        StringWriter stringWriter = new StringWriter();
        try (CSVPrinter csvPrinter = new CSVPrinter(stringWriter, CSVFormat.DEFAULT.withHeader("ID", "Amount", "Type", "Date", "Description"))) {
            for (Transaction t : transactions) {
                csvPrinter.printRecord(t.getId(), t.getAmount(), t.getType(), t.getDate(), t.getDescription());
            }
        } catch (IOException e) {
            throw new RuntimeException("Error exporting to CSV", e);
        }
        return stringWriter.toString();
    }
}