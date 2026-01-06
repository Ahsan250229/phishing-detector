\# Team Roles and Responsibilities



\## DevSecOps Lead

\- CI/CD pipeline

\- Security tool integration

\- Deployment and monitoring



\## Backend Security Developer

\- Authentication

\- RBAC

\- Two-factor authentication



\## Detection Engineer

\- Email analysis logic

\- URL, keyword, header, attachment analysis

\- Risk scoring



\## QA and Documentation Lead

\- Testing

\- Evidence collection

\- Report documentation



\## Team Workflow and Governance



\### Branching Strategy

\- The `main` branch contains stable, reviewed code only.

\- Feature development is performed on short-lived feature branches (e.g., `feature/auth`, `feature/email-analysis`).

\- Branches are merged into `main` only after review and successful CI checks.



\### Pull Requests and Reviews

\- All changes to the `main` branch require a pull request.

\- At least one team member reviews each pull request before approval.

\- Security-relevant changes are reviewed by the DevSecOps Lead.



\### Code Ownership

\- Each major component has an assigned owner based on team roles.

\- Code owners are responsible for reviewing changes and maintaining quality within their component.

\- Shared responsibility applies for cross-cutting concerns such as security and logging.



\### Team Communication and Meetings

\- The team conducts a weekly coordination meeting to review progress and blockers.

\- GitHub Issues are used to track tasks, bugs, and enhancements.

\- Decisions and actions are documented through commits and pull request discussions.



