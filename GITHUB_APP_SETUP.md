# 🔧 GitHub App Configuration Guide

## Your Webhook URL
**Webhook URL:** `https://62d4e0388f4f.ngrok-free.app`

## Step-by-Step Setup

### 1. Update Your GitHub App Settings

1. Go to [GitHub Apps](https://github.com/settings/apps)
2. Find your app and click on it
3. Go to **App settings** → **General**
4. Update these settings:

#### Webhook Configuration
- **Webhook URL:** `https://62d4e0388f4f.ngrok-free.app`
- **Webhook Secret:** Create a strong secret (e.g., `my_secure_webhook_secret_2024`)
- **Content type:** `application/json`

#### Permissions
- **Contents:** Read-only
- **Pull requests:** Read & write
- **Issues:** Read & write

#### Subscribe to events
- ✅ **Pull request**

### 2. Update Your .env File

Replace the placeholder values in your `.env` file with your actual GitHub App credentials:

```bash
# Get these values from your GitHub App settings
GITHUB_WEBHOOK_SECRET=your_actual_webhook_secret_from_step_1
GITHUB_APP_ID=your_actual_app_id_from_github_app
```

### 3. Update Private Key

1. In your GitHub App settings, go to **Private keys**
2. Click **Generate private key**
3. Download the `.pem` file
4. Replace the `PRIVATE_KEY` in `app.py` with your actual private key

### 4. Install the App

1. Go to your GitHub App's **Install App** page
2. Click **Install**
3. Select the repositories you want to monitor
4. Click **Install**

### 5. Test the Setup

1. Make sure your app is running:
   ```bash
   python app.py
   ```

2. Create a test pull request in one of your monitored repositories

3. Check the app logs for webhook events

## Troubleshooting

### If you get 404 errors:
- Make sure your app is running on `0.0.0.0:5000`
- Check that ngrok is forwarding to the correct port
- Verify the webhook URL in GitHub App settings

### If you get authentication errors:
- Check that your `GITHUB_APP_ID` is correct
- Verify your private key is properly formatted
- Make sure the webhook secret matches

### If scans don't work:
- Install missing tools: `pip install bandit semgrep`
- For Node.js tools: Install Node.js and run `npm install -g eslint`
- For Go tools: Install Go and run `go install github.com/securego/gosec/v2/cmd/gosec@latest`

## Current Status

✅ **App is running** on port 5000  
✅ **Receiving webhook requests** (404 errors indicate requests are reaching the server)  
⚠️ **Need to configure** GitHub App credentials in `.env` file  
⚠️ **Need to install** the app on your repositories  

## Next Steps

1. Update your `.env` file with real credentials
2. Install the app on your repositories
3. Create a test pull request
4. Check the generated security reports

## Support

If you encounter issues:
1. Check the app logs for error messages
2. Verify all environment variables are set correctly
3. Test the health endpoint: `curl https://62d4e0388f4f.ngrok-free.app/health` 