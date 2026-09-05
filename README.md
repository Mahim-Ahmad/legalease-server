# LegalEase Server

Express + MongoDB + Stripe backend for the LegalEase online lawyer hiring platform.

## Features
- Role-based access control (User / Lawyer / Admin) via JWT + MongoDB-stored roles
- Lawyer listing CRUD scoped to the owning lawyer, with search/filter/pagination
- Hiring request lifecycle (pending -> accepted/rejected -> paid) with Stripe PaymentIntents
- Comment system gated to clients who have actually hired that lawyer
- Admin routes for user management, transaction history, and platform analytics


