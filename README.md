# ONE CARE SYSTEM — Local EHR (MVP)

This upgrades your EHR into a more realistic, role-based app with a Node/Express API, SQLite database, JWT auth, and an improved UI that saves per-tab.

## What’s included

- Node/Express API with JWT authentication
- Roles: admin, doctor, nurse
- SQLite database (ehr.db) with tables:
  - users (seeded demo users)
  - patients (core columns + JSON blobs per tab)
  - audit_logs (create/update/delete trail)
- REST API endpoints for patients and audit logs
- Frontend updated to use the local API instead of Firebase

## Quick start

Requirements: Node 18+

1. Install deps

```sh
npm install
```

2. Run the app

```sh
npm start
```

The app runs at:
- UI: http://localhost:3000
- API: http://localhost:3000/api

3. Sign in with a demo user

- admin@example.com / admin123
- doctor@example.com / doctor123
- nurse@example.com / nurse123

Notes:
- Admin and Doctor can create/update/delete patients.
- Nurse can view everything, save vitals and nurse-related tabs, but cannot delete or edit Doctor notes.

## API (brief)

Auth
- POST /api/auth/login { email, password } -> { token, user }
- GET /api/auth/me (Bearer token)

Patients
- GET /api/patients?q=&page=&limit=&sort=name_asc|updated_at_desc
- GET /api/patients/:id
- POST /api/patients { info: { name, dob, age, gender, address, contact, patientStatus, roomNo, bedNo, physician, initialDiagnosis, ... } }
- PUT /api/patients/:id { tab: 'info'|'id'|'history'|'assessment'|'labs'|'meds'|'vitals'|'nurse'|'doctor'|'plan', data: {...} }
- DELETE /api/patients/:id

Audit (admin only)
- GET /api/audit

## Data model (pragmatic)

- The `patients` table has core columns (name, demographics, etc.) for sorting/searching, plus JSON columns for each tab. This keeps the UI fast and simple while enabling normalization later if needed (encounters, problems, orders, etc.).

## Known limitations & next steps

- File uploads for Labs are disabled in this local MVP. Next: add `/api/uploads` (multer) and store files under `/public/uploads`.
- Consider splitting data into normalized tables (encounters, vitals, notes, meds, labs) if you need analytics or multi-episode support.
- Add input validation and stronger audit detail (diffs) per update.
- Add pagination UI and server-side sorting options to the dashboard.

## Troubleshooting

- If you change ports, update `server.js` `PORT`.
- To reset demo users, delete `ehr.db` and start the app; seeds will re-create.
- If your browser shows the login screen again, your session token likely expired—just sign in.
