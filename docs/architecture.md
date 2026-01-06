\# System Architecture



\## Architecture Diagram (Logical View)



```mermaid

flowchart LR

&nbsp; U\[User / Analyst] -->|HTTPS| W\[Flask Web App (UI/API)]

&nbsp; W --> A\[Authentication Module\\n(RBAC + 2FA)]

&nbsp; W --> E\[Email Analysis Engine\\n(URL/Keyword/Header/Attachment checks)]

&nbsp; E --> Q\[Quarantine Module]

&nbsp; W --> R\[Reporting Module\\n(PDF/CSV)]

&nbsp; A --> DB\[(SQLite Database)]

&nbsp; E --> DB

&nbsp; Q --> DB

&nbsp; R --> DB

&nbsp; W --> L\[Logging \& Monitoring]





\## Components

\- Web Application (Flask)

\- Authentication Module

\- Email Analysis Engine

\- Quarantine Module

\- Reporting Module

\- Database (SQLite)



\## Security Design

\- Password hashing

\- RBAC

\- 2FA

\- Secure session management

\- Logging and monitoring



\## Data Flow

1\. User authenticates

2\. Email submitted

3\. Analysis engine processes email

4\. Risk score generated

5\. Email quarantined if required

6\. Report generated

