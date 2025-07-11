export function analyzePathTraversal(code: string): boolean {
    const pathTraversalPatterns = [
        /(\.\.\/|\.\.\\)/, // Detects ../ or ..\
        /(%2E%2E|%2e%2e)/i, // URL encoded ../
        /(%2F|%5C)/ // Detects / or \
    ];

    for (const pattern of pathTraversalPatterns) {
        if (pattern.test(code)) {
            return true; // Potential path traversal vulnerability found
        }
    }
    return false; // No vulnerabilities detected
}