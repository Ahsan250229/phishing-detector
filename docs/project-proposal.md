# Project Proposal: Phishing Email Detector

## Project Overview
This project aims to develop a secure phishing email detection system using DevSecOps principles. The system analyzes emails to identify phishing attempts using heuristic-based pattern recognition. This system is intended for use within organizational email environments, such as small-to-medium enterprises and academic institutions, to assist security teams in identifying and managing phishing threats.

## Objectives
- Detect phishing emails using URL, keyword, header, and attachment analysis
- Implement secure authentication with RBAC and 2FA
- Integrate security testing into CI/CD pipeline
- Demonstrate DevSecOps practices across the lifecycle

## Core Features
- Secure login with RBAC and 2FA
- Email analysis engine
- Risk indicators (Red/Yellow/Green)
- Email quarantine
- Exportable reports (PDF/CSV)

## Technology Stack
- Backend: Python (Flask)
- Database: SQLite
- CI/CD: GitHub Actions
- Security Tools: Bandit, pip-audit, OWASP ZAP

## Security Focus
- The project also emphasizes security compliance and audit readiness by maintaining logs and controls that support security reviews and alignment with common standards and best practices.
- OWASP Top 10 vulnerabilities
- Secure authentication
- Access control
- Input validation
- Logging and monitoring

## Scope Boundaries and Out of Scope

This project focuses on detecting phishing emails using heuristic-based techniques within a controlled prototype environment. Advanced machine learning models, real-time enterprise email server integration, large-scale deployment, and automated incident response actions are considered out of scope for this project.
