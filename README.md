# SpendWhy

Reads your bank alert emails and gives you 2 minutes to upload the bill. If no bill arrives, a Sarvam voice agent calls to ask why you spent the money.

## Run

```bash
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Open http://127.0.0.1:8000. Each person signs up with their name, Gmail, a [Gmail app password](https://myaccount.google.com/apppasswords) and phone number, and sees only their own transactions. Gmail is checked every minute.

With `DEMO_MODE=true` the app password is optional and calls are simulated.

## Real calls and sharing

Set `DEMO_MODE=false`, the Sarvam keys, and `PUBLIC_URL`. Host it on an always-on server with a persistent disk mounted at `DATA_DIR` (the `Dockerfile` works on Render, Railway or Fly), or use a tunnel to port 8000. Run one instance only.

**This MVP is not hardened.** App passwords give full read access to a mailbox and are stored on the server, encrypted with a key on the same disk. Phone numbers aren't verified. Only share it with people who trust you, and use HTTPS.

## Sarvam agent setup

**Input variables:** `user_name`, `amount`, `merchant`, `txn_time`

**Extract:** `spend_reason`, `category`, `worth_it` (yes/no)

**Prompt:**

> You are a friendly finance buddy calling {{user_name}}. ₹{{amount}} was spent at {{merchant}} on {{txn_time}} and no bill was shared. Ask what it was for and save a short reason in spend_reason. Pick one category (Food & Dining, Groceries, Shopping, Transport, Bills & Utilities, Entertainment, Health, Education, Transfers, Other). Then ask 'Looking back, was it worth it?' and save yes or no in worth_it. Keep it under 45 seconds. Never ask for OTPs, PINs or card details. Reply in the user's language.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/config`, `/api/transactions`, `/api/stats` | Dashboard data |
| POST | `/api/sync` | Check Gmail now |
| POST | `/api/connect`, `/auth/logout` | Sign up or sign in, sign out |
| POST | `/api/ingest/email` | Add an alert read elsewhere, such as the Gmail MCP |
| POST | `/api/demo/alert`, `/api/demo/reset` | Fake alert, clear the dashboard |
| POST | `/api/transactions/{id}/call`, `/reason`, `/ignore` | Row actions |
| POST | `/api/webhooks/sarvam` | Call results |
| POST, GET | `/api/documents` | Upload or list bills. A WhatsApp bot can post `file` to `/api/documents?wait=true` to get the result in the response. |
