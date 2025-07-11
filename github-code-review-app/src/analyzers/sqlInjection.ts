function analyzeSqlInjection(code: string): boolean {
    const unsafePatterns = [
        /['";]/, // Basic unsafe characters
        /SELECT\s+\*\s+FROM\s+/i, // SELECT statements
        /INSERT\s+INTO\s+/i, // INSERT statements
        /UPDATE\s+/i, // UPDATE statements
        /DELETE\s+FROM\s+/i // DELETE statements
    ];

    return unsafePatterns.some(pattern => pattern.test(code));
}

export { analyzeSqlInjection };