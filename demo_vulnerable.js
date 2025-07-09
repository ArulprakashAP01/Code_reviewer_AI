// Demo JavaScript file with vulnerabilities

// HIGH SEVERITY: XSS vulnerability
function displayUserInput(userInput) {
    // This is intentionally vulnerable
    document.getElementById('output').innerHTML = userInput; // HIGH: XSS
    eval(userInput); // HIGH: Code injection
}

// MEDIUM SEVERITY: Hardcoded credentials
const API_KEY = "sk-1234567890abcdef"; // MEDIUM: Hardcoded secret
const PASSWORD = "admin123"; // MEDIUM: Hardcoded password

// LOW SEVERITY: Weak crypto
function hashPassword(password) {
    // This is intentionally weak
    return btoa(password); // LOW: Weak encoding
}

// HIGH SEVERITY: SQL injection
function queryDatabase(userInput) {
    const query = `SELECT * FROM users WHERE name = '${userInput}'`; // HIGH: SQL injection
    return executeQuery(query);
}

// MEDIUM SEVERITY: Insecure random
function generateToken() {
    return Math.random().toString(36); // MEDIUM: Insecure random
}

// Usage
const userInput = prompt("Enter your name:");
displayUserInput(userInput);
queryDatabase(userInput);
