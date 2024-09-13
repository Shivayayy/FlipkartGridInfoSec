<img width="787" alt="Screenshot 2024-09-13 at 4 56 58 PM" src="https://github.com/user-attachments/assets/4745844b-ea43-43b2-9501-8fc68dd8c831">
# Flipkart Grid Infosec Finalist Project

## Overview

This repository is the source code for the **Flipkart Grid Infosec Hackathon Finalist Project**. Our project focuses on developing a highly secure, AI-driven API security scanner that leverages advanced techniques like K-Means clustering for IP blacklisting and Salesforce's T5 model for scanning large codebases. The solution ensures that APIs are robust, safe from vulnerabilities, and compliant with industry security standards.

## Key Features

- **API Endpoint Discovery**: Automatically scans the codebase to discover API endpoints and logs them in a structured format for vulnerability analysis.
  
- **Vulnerability Scanning**: Our solution integrates cutting-edge tools to perform thorough security checks on API endpoints, including OWASP Top 10 risks. 

- **K-Means Clustering for IP Blacklisting**: We leverage K-Means clustering algorithms to detect anomalies and identify potential Denial of Service (DoS) attacks. This intelligent system dynamically updates the blacklist to prevent repeated attacks from malicious IP addresses.

- **Salesforce T5 Model for Code Scanning**: Our project uses a fine-tuned T5 model to perform an exhaustive scan of the entire codebase. It helps in analyzing the code for vulnerabilities, API misconfigurations, and hidden security risks.

- **Automated Report Generation**: API vulnerability reports are generated automatically in JSON format, detailing potential risks, vulnerabilities, and compliance with security standards. 

- **Crowdsourced Learning**: The system can adapt and improve over time by learning from API detection data from multiple sources, including open-source contributions.

---

## API Security Management Dashboard

### Overview

The **API Security Management Dashboard** is a powerful tool designed to help organizations manage, monitor, and secure their APIs. With real-time traffic monitoring, comprehensive endpoint details, automated security processes, and seamless CI/CD integration, this dashboard provides everything you need to keep your APIs secure and compliant.

### Features

#### 1. Endpoint Management:
- **Centralized Endpoint Overview**: View and manage all the endpoints across your organization in one location.
- **Real-Time Traffic Monitoring**: Track live traffic and identify potential security threats or performance issues.
- **Comprehensive Endpoint History**: Review the history and status of each API endpoint for better tracking and auditing.

#### 2. Real-Time Notifications:
- **Instant Alerts**: Receive notifications when new endpoints are added to your Software Development Life Cycle (SDLC).
- **Proactive Security Alerts**: Get real-time notifications for security risks or vulnerabilities in newly added endpoints.

#### 3. CI/CD Integration:
- **Automated Endpoint Extraction**: Automatically extract and scan new API endpoints by integrating with your CI/CD pipeline.
- **Continuous Security Scanning**: Trigger and schedule full scans during the CI/CD process to ensure continuous API security.

#### 4. Security Scanning:
- **DAST and SAST Scans**: Perform comprehensive Dynamic Application Security Testing (DAST) and Static Application Security Testing (SAST) to detect vulnerabilities.
- **In-Dashboard Reports**: Access detailed vulnerability reports directly within the dashboard, helping to remediate security issues quickly.

#### 5. Ticket Management:
- **Custom Ticket Generation**: Automatically create tickets for detected vulnerabilities based on security scans.
- **Track and Resolve Issues**: Track the progress of ticket resolution and ensure timely mitigation of security risks.

---

## Project Structure

- **Backend (Django)**: The project utilizes a Django server to manage requests, scan codebases from GitHub, and run security analyses on discovered API endpoints. All scan results are stored in MongoDB for further evaluation and auditing.

- **Docker Support**: The entire application is containerized for ease of deployment. A Docker image is available on Docker Hub, allowing for quick setup and consistent environments across different machines.

- **Celery & RabbitMQ Integration**: Asynchronous task handling with Celery and RabbitMQ is used for performing background scans and handling high volumes of API requests efficiently.

- **MongoDB**: Used for storing API metadata, scan results, and request logs, ensuring scalability and reliability in storing large datasets.

---

## Technologies Used

- **Django**: Web framework used for building the server and API logic.
- **MongoDB**: NoSQL database for storing scan data and API requests.
- **Celery & RabbitMQ**: Task queue system for handling asynchronous operations.
- **K-Means Clustering**: For detecting and blacklisting malicious IP addresses.
- **Salesforce T5 Model**: To scan and analyze the entire codebase for vulnerabilities.
- **Docker**: For containerizing the application and managing deployment with ease.

---

## How It Works

1. **API Scanning**: 
    - Users provide the GitHub URL of a codebase.
    - The server scans the entire repository to detect all API endpoints using predefined patterns and machine learning models.

2. **Vulnerability Analysis**:
    - The project uses vulnerability scanning tools to analyze the discovered API endpoints, checking for issues such as insecure configurations, broken authentication, or exposure to attacks like SQL injection and Cross-Site Scripting (XSS).

3. **K-Means Clustering for Blacklisting**:
    - The system keeps track of incoming API requests, logging IP addresses and request behaviors.
    - K-Means clustering is employed to detect outlier behavior, allowing the system to dynamically block malicious IPs and prevent potential DoS attacks.

4. **Salesforce T5 Model**:
    - The Salesforce T5 model is trained to scan large codebases efficiently.
    - The model analyzes the entire repository to detect hidden vulnerabilities, misconfigurations, and potential security loopholes.

5. **Vulnerability Reporting**:
    - The results of each scan are saved in MongoDB and returned as JSON files, offering detailed reports on potential vulnerabilities and risk scores for each API endpoint.

---

## Contributions

Contributions and suggestions are welcome. Please fork the repository and submit a pull request.

## Docker Image

A Docker image for this project is available on Docker Hub. You can use it to quickly spin up the entire solution in a containerized environment.

<img width="787" alt="Screenshot 2024-09-13 at 4 56 58 PM" src="https://github.com/user-attachments/assets/33efbd36-5d25-49dc-817f-88593d732ca9">

<img width="791" alt="Screenshot 2024-09-13 at 4 57 07 PM" src="https://github.com/user-attachments/assets/fbb8e948-9c96-4584-a91f-c8ed2d55ed60">

<img width="787" alt="Screenshot 2024-09-13 at 4 57 24 PM" src="https://github.com/user-attachments/assets/37d1354c-eac8-4afa-84a8-920404c7d23c">

<img width="794" alt="Screenshot 2024-09-13 at 4 57 37 PM" src="https://github.com/user-attachments/assets/33c830ee-39eb-46ac-82c3-a90ba43a43c8">

<img width="792" alt="Screenshot 2024-09-13 at 4 57 43 PM" src="https://github.com/user-attachments/assets/6fcf7171-4f5b-47ec-9f45-4bf2c8a81f9b">

<img width="796" alt="Screenshot 2024-09-13 at 4 57 50 PM" src="https://github.com/user-attachments/assets/f56eaef6-ce02-41ee-92c6-72ca18490603">

<img width="799" alt="Screenshot 2024-09-13 at 4 58 00 PM" src="https://github.com/user-attachments/assets/ec9c7c26-10f1-49d4-9c7a-1239ee7c57a6">


