export interface WebhookEvent {
    action: string;
    repository: {
        id: number;
        name: string;
        owner: {
            login: string;
        };
    };
    sender: {
        login: string;
    };
    [key: string]: any; // Additional properties can be added as needed
}

export interface AnalysisResult {
    vulnerabilityType: string;
    filePath: string;
    lineNumber: number;
    message: string;
}