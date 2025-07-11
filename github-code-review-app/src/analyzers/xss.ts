export function analyzeXSS(code: string): string[] {
    const vulnerabilities: string[] = [];
    
    // Simple regex to identify potential XSS patterns
    const xssPatterns = [
        /<script.*?>.*?<\/script>/gi,
        /javascript:/gi,
        /on\w+=".*?"/gi,
        /<img.*?src=["'].*?["']/gi
    ];

    xssPatterns.forEach(pattern => {
        if (pattern.test(code)) {
            vulnerabilities.push('Potential XSS vulnerability detected.');
        }
    });

    return vulnerabilities;
}