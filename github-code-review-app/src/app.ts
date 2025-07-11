import express from 'express';
import bodyParser from 'body-parser';
import { handleWebhook } from './github/webhookHandler';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

app.post('/webhook', handleWebhook);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});