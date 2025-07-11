import { WebhookEvent } from '../types';
import { analyzeSqlInjection } from '../analyzers/sqlInjection';
import { analyzeXSS } from '../analyzers/xss';
import { analyzePathTraversal } from '../analyzers/pathTraversal';

export function handleWebhook(event: WebhookEvent) {
    switch (event.type) {
        case 'push':
            // Handle push event
            const codeChanges = event.payload.commits.map(commit => commit.message).join('\n');
            analyzeSqlInjection(codeChanges);
            analyzeXSS(codeChanges);
            analyzePathTraversal(codeChanges);
            break;
        case 'pull_request':
            // Handle pull request event
            const prChanges = event.payload.pull_request.body;
            analyzeSqlInjection(prChanges);
            analyzeXSS(prChanges);
            analyzePathTraversal(prChanges);
            break;
        // Add more event types as needed
        default:
            console.log(`Unhandled event type: ${event.type}`);
    }
}