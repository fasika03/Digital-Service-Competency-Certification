# Digital Service Competency Certification: Portal

Node.js + Express + SQLite. Serves the website and a JSON API.

## Run
```
npm install
ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='choose-a-strong-one' \
JWT_SECRET='long-random-string' BASE_URL=https://your-domain npm start
```
Open http://localhost:3000. Companies register at /app.html; the admin signs in at the same page.

## Flow
Register -> create application -> upload documents -> submit -> admin approves/rejects -> company downloads PDF certificate -> company appears in the public registry.

## API
Public: GET /api/registry?q=, /api/stats, /api/news, /api/verify/:certNo
Auth: POST /api/auth/register, /api/auth/login, GET /api/me
Company: POST/PUT /api/applications, GET /api/applications/mine, POST /api/applications/:id/documents, POST /api/applications/:id/submit, GET /api/applications/:id/certificate
Admin: GET /api/admin/applications, POST /api/admin/applications/:id/decision, POST/DELETE /api/admin/news

## Before going live
Serve over HTTPS, set a fixed JWT_SECRET, back up data.db and uploads/, and consider email notifications and virus scanning for uploads.
