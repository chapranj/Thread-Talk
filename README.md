Internal Employee Discussion Forum
Overview

This project aims to create an internal discussion forum tailored for companies to facilitate communication among employees. Users are categorized into two roles: Employee and Manager, each with distinct privileges within the forum.
Features
User Roles and Privileges

    Employee:
        Posting: Employees with an account can create and post content in various threads.
    Manager (Includes all Employee privileges plus):
        Content Management: Managers have the ability to delete posts and entire threads for moderation purposes.

Technology Stack

    Backend Framework: Spring Security is utilized to manage user authentication, authorization, and role-based access control.
    Database: MySQL
    Frontend: Thymeleaf

Implementation Details
Security Features

    Authentication: Secure user login and registration mechanisms.
    Authorization: Role-based access control ensures that only authorized users can perform specific actions.
    Secure Endpoints: APIs and routes are secured to prevent unauthorized access.

How to Use

    Employee Access:
        Employees can register/login to access the discussion forum.
        Once logged in, they can create posts, comment on threads, etc.

    Manager Access:
        Managers can perform all actions available to employees.
        Additionally, they have the authority to delete posts and threads as required.
