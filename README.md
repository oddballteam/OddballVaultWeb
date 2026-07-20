# Zero-Knowledge Web Vault

This is an enterprise web vault built with React, Vite, and Supabase. It integrates with Okta OIDC to give you role-based folder access across teams.

## Architecture Overview

* **Frontend:** React with Vite
* **Identity Provider:** Okta OIE using OIDC
* **Database and Auth:** Supabase (PostgreSQL with Row Level Security)
* **Hosting:** Netlify
* **Security Model:** Zero-Knowledge client-side encryption. Passwords and sensitive payloads are encrypted locally in the browser before they hit the database.

## Getting Started

### Prerequisites

Make sure you have these installed locally:
* Node.js (v18 or higher recommended)
* Git
* Supabase CLI (optional, if you want to run database migrations locally)

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_ORG_NAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

### 2. Set Up Environment Variables

Copy `.env.template` to `.env.local` and fill in your own Supabase project values:

```
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-supabase-anon-key
```

Supabase brokers the Okta OAuth handshake itself (configured in the Supabase Dashboard under Authentication → Providers), so no Okta client ID, secret, issuer, or domain belongs in this file or anywhere in the frontend.

Do not commit your `.env.local` file to Git. It is already covered by `.gitignore`.

### 3. Install Dependencies and Run

```bash
# Install packages
npm install

# Start local dev server
npm run dev
```

## Database and Migrations

Database schemas and Row Level Security policies live inside the `supabase/migrations` folder.

If you are using the Supabase CLI locally, run:

```bash
supabase db reset
```

## Security and Governance

* **Zero-Knowledge Architecture:** Encryption keys stay in the browser. The database only stores encrypted payloads.
* **Sensitive File Protection:** Never commit `.env` files, `.ovault` backups, or unencrypted `.csv` exports. The `.gitignore` is set up to block these automatically.
* **Okta Integration:** Group claim handling relies on the `groups` scope/claim being enabled in Okta and mapped through to Supabase's session JWT.

## Deployment

This repo deploys to Netlify automatically whenever you push code to the `main` branch. Just make sure your `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` variables are added to your site settings in Netlify.
