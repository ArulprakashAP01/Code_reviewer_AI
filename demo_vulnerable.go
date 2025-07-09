package main

import (
    "database/sql"
    "fmt"
    "os"
    "os/exec"
    "strings"
)

// HIGH SEVERITY: Command injection
func vulnerableFunction(userInput string) {
    // This is intentionally vulnerable
    cmd := exec.Command("echo", userInput) // HIGH: Command injection
    cmd.Run()
    
    // HIGH SEVERITY: SQL injection
    db, _ := sql.Open("sqlite3", "database.db")
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput) // HIGH: SQL injection
    db.Query(query)
}

// MEDIUM SEVERITY: Hardcoded credentials
const (
    APIKey = "sk-1234567890abcdef" // MEDIUM: Hardcoded secret
    Password = "admin123"           // MEDIUM: Hardcoded password
)

// LOW SEVERITY: Weak crypto
func hashPassword(password string) string {
    // This is intentionally weak
    return strings.ToLower(password) // LOW: Weak hashing
}

func main() {
    userInput := os.Args[1]
    vulnerableFunction(userInput)
}
