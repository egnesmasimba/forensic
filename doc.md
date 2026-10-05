# EFMTT 2.0: Enterprise Forensic Monitoring, Tracking & Response Platform

## Complete Product Documentation

This file is the product specification. It describes the intended platform, not the local Investigation Center that is running today. What has been built is recorded in [done-todolist.md](done-todolist.md). What remains open is in [todolist.md](todolist.md). A completed local item is not a certification, a live deployment, or proof that the full specification is shipped.

---

## 1. Introduction

### 1.1 What EFMTT Was

The original Enterprise Forensic Monitoring & Tracking Solution (EFMTT) was an innovative end-to-end enterprise fraud management solution providing a unique combination of comprehensive data capture directly from the corporate network with cross-channel analytics and real-time alerting. It allowed organizations to detect and prevent internal and external fraud, information leakage and IT sabotage, and comply with government regulations.

EFMTT provided a first-of-its-kind cross-platform surveillance system for unparalleled visibility of end-user activity in corporate applications across the enterprise. The system tracked all user and account activity in corporate applications across all major platforms, from Mainframe to iSeries to Web. Security officers, fraud investigators and internal auditors utilized EFMTT in three major ways:

**Visual Replay** – The system captured a detailed audit trail allowing complete visibility into end-user activity with visual replay of every screen, keystroke and flow of screens in core business applications across all major platforms. The system provided Google-like search on the content of every user screen and session, enabling investigators to immediately get answers to questions such as: which user accessed a specific account number in a given timeframe, and then replay the exact activities of the user screen by screen. This functionality enabled compliance with GLBA, HIPAA, PCI and other regulations that require a detailed audit trail of access to sensitive customer data.

**Cross-Channel Behavior Tracking in Real-Time** – The behavior of customers, accounts, employees and other entities was tracked and profiled by the analytic engine, which correlated activities between the various channels and generated real-time alerts on suspicious events in various channels including Call center, e-Banking, ACH, checks, new accounts, employees and others. This enabled compliance with government regulations such as Identity Theft Red Flags.

**Investigations and Case Management** – Suspicious events could be investigated utilizing a user-friendly web-based user-interface, allowing investigators to manage and document the investigation process, view all information relevant to an alert, case or profile in one consolidated view with flexible drilldown options on each related entity. The system enabled investigators with no technical background to fully control the investigation environment and processes and control business rules parameters and thresholds, set scoring calculation functions, maintain white lists, configure automatic case creation, define reports, etc.

Utilizing an agent-less non-invasive sniffing technology, EFMTT required no change to organization infrastructure, generating no risk, no overhead, and no performance degradation on servers, networks or clients.

### 1.2 What EFMTT 2.0 Adds

EFMTT 2.0 retains all original capabilities while adding **68 new features** that transform it from a forensic recording platform into a complete insider risk management, data loss prevention, and automated response ecosystem.

The enhanced platform now delivers:

- **Active blocking** rather than passive recording
- **Endpoint-level forensics** complementing network capture
- **AI/ML-driven behavioral analytics** with predictive capability
- **Automated response workflows** that act in real time
- **Comprehensive compliance coverage** across major regulatory frameworks
- **Seamless integration** with existing security infrastructure

---

## 2. Main System Functions

The main functions provided by the system are:

1. Data Capture (Network + Endpoint)
2. Data Analysis
3. Profiling, Scoring and Alerting
4. Investigation and Case Management
5. Data Loss Prevention and Active Blocking
6. Real-Time Response and Automation
7. Identity and Access Management
8. Compliance and Audit Support
9. Integration and Extensibility

---

## 2.1 Data Capture

### 2.1.1 Network Sniffing (Original EFMTT)

EFMTT records the activity of end-users with the corporate servers and inter-server communication (e.g. SWIFT messages) by non-invasively sniffing network traffic. The sniffing is performed by connecting the EFMTT Sensor to the main corporate network switches through mirror ports or tap devices. The recorded user sessions and inter-server messages are analyzed and reconstructed in real-time, allowing visual replay of user activity screen by screen.

EFMTT monitors activity in a wide range of platforms:

- IBM Mainframe screen protocol – 3270 on SNA, TCP/IP (TN3270) and Enterprise Extender
- IBM iSeries screen protocol – 5250 on SNA, TCP/IP (TN5250), and MPTN
- Client/Server and Inter-Server messages – TCP/IP, MQ Series, MSMQ, IBM mainframe SNA LU0 and LU6.2, SMB
- HTTP, HTTPS, Web services
- Telnet/VT100 and other VT flavors, SSH
- Oracle Forms
- FTP
- Database access: Oracle (SQLNET), DB/2 (DRDA) and MS SQL (TDS)
- SWIFT, FIX and ISO8583

Monitoring other application protocols can be easily configured.

The system can monitor various types of end-users:

- Business users
- Privileged IT users
- External users accessing the corporate systems via the Web (e.g. e-Banking customers)

### 2.1.2 Endpoint Agent Deployment (New in 2.0)

**Feature 11: Endpoint Agent Deployment**

EFMTT 2.0 introduces optional endpoint agents that can be deployed on each device to capture activity that network sniffing alone cannot see. These agents provide finer-grained data including:

- Local file operations (copy, move, delete, rename)
- USB device connections and data transfers
- Clipboard activity across applications
- Print jobs and spooled documents
- Screenshots and screen captures
- Application-level process launches and terminations
- Window titles and active application tracking
- Idle vs active time detection

The agent operates in **stealth mode** (Feature 64), invisible in Task Manager, and includes **tamper-proof installation** (Feature 65) that prevents regular users from detecting or uninstalling the software.

### 2.1.3 Data Collection from External Sources (Original EFMTT)

EFMTT can capture data from text and binary files, log files, database tables, XML and CSV files, Message Queues and other sources. The data can be captured in real-time or at scheduled times. The system can be configured to parse files with complex layouts. The data can be analyzed in real-time and be correlated by the rule engine with information captured through network sniffing.

### 2.1.4 Process-Level Forensics (New in 2.0)

**Feature 12: Process-Level Forensics**

The endpoint agent records each process's launch, command-line parameters, parent-child process relationships, and termination. This enables investigators to trace exactly how a suspicious application was launched, what it accessed, and how it was closed.

**Feature 13: File System Change Tracking**

Complete history of file creation, modification, deletion, and permission changes is recorded, providing a full forensic trail of document activity.

**Feature 14: Registry Monitoring**

Windows Registry changes are tracked to detect persistence mechanisms, unauthorized configuration changes, and malware installation attempts.

### 2.1.5 Remote Desktop and Virtualized Environment Monitoring (New in 2.0)

**Feature 15: RDP Session Recording**

Dedicated recording of Remote Desktop Protocol sessions, capturing all activity within remote sessions.

**Feature 16: Citrix Environment Monitoring**

Specialized monitoring for Citrix virtual desktop environments, ensuring visibility even in virtualized infrastructures.

**Feature 67: Incognito Mode Monitoring**

Captures activity even when users employ private browsing modes or attempt to evade monitoring.

---

## 2.2 Data Analysis

The system provides out-of-the-box free-text indexing and configurable user process analysis, now enhanced with endpoint data streams.

### 2.2.1 Free-Text Indexing (Original EFMTT)

EFMTT analyzes the content of the recorded screens/web-pages and keystrokes and identifies screen/web-page headers and field captions and values. All of this information is stored in the system database and can be indexed for Google-like free-text search. It allows, for example, searching for all users who accessed a specific customer account in a specific timeframe. This search can be performed on recorded data from a specific platform (e.g. Web) or on data recorded from several platforms (e.g. Mainframe, Client/Server, Web, AS/400, etc.).

### 2.2.2 Optical Character Recognition (New in 2.0)

**Feature 61: Optical Character Recognition (OCR)**

EFMTT 2.0 now extracts text from screenshots and image files, enabling search of sensitive information captured in images. This extends Google-like search to visual content that would otherwise be opaque to text search.

### 2.2.3 User Process Analysis (Original EFMTT)

One of the unique functions of EFMTT is analyzing end-user activity and identifying business processes performed by users. This is done in two steps – identifying specific screens and identifying business processes which comprise the identified screens.

**Identifying Screens/Web Pages**

The system implementer may identify a specific screen by specifying certain text or several text strings (e.g. transaction name and/or screen header) which appear in specific locations on the screen. The screen definition may also include several fields to be captured by the system according to their locations on the screen. Once the implementer has deployed the screen definition in the EFMTT repository, the system starts to check every recorded screen against this definition in real-time.

**Identifying Business Processes (User Activity Events)**

A User Activity Event is a business transaction performed by a user by accessing one or more application screens. The system implementer may identify a User Activity Event by specifying a scenario by which a user navigates from screen to screen in order to perform a certain business function.

It should be noted that there is no need to identify screens/web pages in order to perform the search and replay functions mentioned above. Identification is only required for screens/web pages which comprise business processes that the implementer would like to identify, and is performed for two main purposes:

1. Triggering business rules in the rule engine for detecting suspicious user/account behavior.
2. Creating an audit trail of business transactions with specific information captured from the transactions. This audit trail is typically a table which is automatically generated by EFMTT in which each row represents one occurrence of a screen or user activity event. The information captured may include, for example, User ID, account number, customer name, transaction amount, actions performed by the end user (add, update, delete), etc. This specific audit trail is an addition to the generic audit trail generated automatically by EFMTT through recording of complete user sessions.

User Activity Events are defined using a wizard that guides the user through the process. All entities including User Activity Events, screens, fields, etc. are stored in the EFMTT repository.

### 2.2.4 Thin vs. Fat Client Support (Original EFMTT)

EFMTT monitors thin and fat-client applications in different ways. For thin-client applications (3270, 5250, HTML and VT) EFMTT reconstructs user screens based on the captured network transmissions and provides visual screen replay. In fat-client applications the screen displayed to the user is normally built by the client application so it is impossible to reconstruct it based on the network transmissions alone.

EFMTT monitors user activity in client-server applications by recording the messages sent between the client and the server. In order to analyze the content of the messages EFMTT allows the implementer to import the layout structure of these messages from the application program (Cobol, C, VB, etc.) to the EFMTT repository. The implementer only needs to import the layouts for messages which require analysis. At first, the system can be used just for recording everything. The decision which messages will be analyzed can be made at a later stage, as the imported layouts may be applied to recorded data after the fact. In conjunction with the layout the implementer needs to specify how each message should be identified (e.g. message-type and/or transaction-type field, etc).

EFMTT provides search and display capabilities for the content of the messages, enabling the security officer to search any field value that was indexed and display the messages and their fields' content in the original sequence they occurred – client-to-server message, then server-to-client reply message and so on. Based on this display, the investigator is able to track end user activity, not as it was displayed on the screen but rather the data that was sent to and from the user's machine. EFMTT Business Rules can analyze user activity and behavior patterns based on the fields in these messages similarly to the fields in screens/web pages.

---

## 2.3 Profiling, Scoring and Alerting

The analytic engine provides a highly flexible and adaptable data model which supports advanced calculations and correlations in real-time. The data model can maintain static and dynamic information on various types of entities including employees, accounts, customers, and others. It can be adapted to specific process and requirements of the organization.

The data captured by the system from various sources is sent to the rule engine in a normalized way, so the platform from which the data has been captured and the way it has been captured become transparent to the analytic engine.

The analytic engine accepts two types of input:

1. **User Activity Events** (described above) which are continuously captured by the system from the different data channels. These events are mapped as "Facts" within the analytic engine.

2. **Data from external databases and files**, for example indication of accounts which belong to celebrities or organization's executives. This type of indication is typically not displayed on the user screens captured by the system, yet it is important for detecting suspicious behavior. The information received from external sources is mapped into "Business Entities", for example, User, Customer, Account, etc.

A business rule typically includes one or more aggregation functions (Sum, Count, Min, Max, etc.) which perform calculations on the relevant Facts and Business Entities.

One of the unique functions of EFMTT is applying new rules to historic recorded data. This is possible since all user activity is recorded and stored regardless if it is suspicious or not. It allows internal auditors to check whether new potential fraud scenarios (which were not previously foreseen) occur in the organization's pre-recorded data.

### 2.3.1 Business Rule Examples (Original EFMTT)

| Rule Type | Generate an Alert when... |
|-----------|---------------------------|
| **What?** | Access of a specific account; Access an account included in a White or Black list; Access any account more than x times in an hour/day |
| **How?** | Search for accounts according to customer name more than X times in an hour/day |
| **When?** | All the above – after hours |
| **Where from?** | All the above from which department? (HR, IT, etc.) |
| **Time correlation** | Same user-id login from different terminals at the same time; An agent in the call center accesses customer sensitive data without receiving a call from the customer |
| **Data correlation** | Add same address/beneficiary to different accounts by the same user |
| **Aggregation** | Sum of transfers from/to an account/by user exceeds $X |
| **Process** | Add beneficiary then transfer/withdraw money then delete beneficiary – all in 48 hours; Change address then transfer/withdraw money then delete address – all within 48 hours; Increase credit limit then transfer/withdraw money then decrease credit limit – all within 48 hours |

### 2.3.2 Dynamic Risk Scoring (New in 2.0)

**Feature 21: Dynamic Risk Scoring**

EFMTT 2.0 calculates a continuously updated risk score for each user, account, and entity based on real-time behavior rather than only static rule thresholds. Scores adjust dynamically as behavior changes, enabling more accurate prioritization of alerts and investigations.

**Feature 22: 150+ Behavioral Indicators**

The platform now tracks over 150 behavioral indicators per user, including:

- Average number of accounts accessed per day in the past 3 months
- Average number of dormant accounts accessed per week in the past 3 months
- Average number of account address changes per week in the past 3 months
- Average number of account beneficiary changes per week in the past 3 months
- Average number of account mailing frequency changes per week in the past 3 months
- Average number of dormant account attribute changes per week in the past 3 months
- Average number of queries on customer names per week in the past 3 months
- Average total amount of money transfers per day in the past 3 months
- Average number of money transfers per day in the past 3 months
- Average number of changes to account attribute and change back within 48 hours per month in the past 3 months

### 2.3.3 Automatic Behavior Baseline (New in 2.0)

**Feature 26: Automatic Behavior Baseline**

Machine learning algorithms automatically establish each user's normal behavior pattern without manual threshold configuration, reducing false positives and enabling detection of subtle deviations.

**Feature 27: Cross-Channel Behavior Correlation**

The system correlates behavior across phone, email, chat, and system actions to build a unified view of user activity.

### 2.3.4 Predictive Analytics (New in 2.0)

**Feature 23: Predictive Analytics**

Based on behavioral changes, the system predicts when users may become threats, enabling proactive intervention before incidents occur.

**Feature 24: Burnout/Attrition Risk Analysis**

Detects patterns of overwork, disengagement, and behavioral changes that predict employee turnover or burnout, which are often precursors to insider incidents.

**Feature 25: Active vs Idle Time Distinction**

Automatically distinguishes between real work, meeting participation, and idle time, improving productivity analysis and anomaly detection.

**Feature 28: Behavioral Biometrics**

Verifies user identity through keystroke rhythm, mouse movement patterns, and typing cadence, detecting account takeover or credential sharing.

**Feature 29: Synthetic Data/Privacy-Preserving Analytics**

Uses "synthetic twins" for analysis without exposing real personal data, enabling compliance with privacy regulations while maintaining analytical capability.

**Feature 30: Employee Sentiment Analysis**

Analyzes behavioral signals to infer emotional state and flag disgruntled or distressed employees who may pose elevated risk.

### 2.3.5 Profiling (Original EFMTT, Enhanced)

The Profiling Engine supports profiling of end-users and end-user groups, accounts and account groups, customer and customer groups and any other entity. The system provides a predefined set of profile indicators which can be adapted to an organization's specific requirements.

The system continuously calculates various profile indicators information and generates real-time alerts if suspicious anomalies are detected. This is performed by comparing current user behavior to his previous behavior and user (or customer or account) behavior to other users in the same department or users with the same role in other departments.

In addition, the system can continuously calculate a score for each entity (user, customer, account, etc.) according to the scores contributed by the various profile indicators or combination of indicators. Alerts may be generated in real-time on specific entities if the score of an entity surpasses the cutting score for the entity type.

The alerts generated by the rule engine can be sent to the EFMTT Investigation Center and Case Manager or to third-party Case Manager. Alternatively they can be sent by email or SMS, or can initiate a pre-defined process in another system using protocols such as MQ or Web services. It can be used for example, for suspending a suspicious user.

### 2.3.6 Example: Detecting and Blocking Phone Banking Impersonators (Original EFMTT)

EFMTT captures in real-time information on the current calls received by call-center agents from the IVR (Interactive Voice Response) and the interaction of the agent with the CRM system while he is on the phone with the caller. The information collected includes attributes such as: caller phone number, language, customer details entered by the caller, authentication success or failure, attempted transaction information, etc.

The system maintains a profile for each customer and caller and adds the information captured in real-time to the existing profile. The system continuously checks for suspicious combinations of fraud indicators, for example, number of calls received from the same SSN in the past few days, number of calls received from the same phone number in the current day, number of password changes in the past few days, number of password failures in the past few days, etc. Each combination adds a score to the caller profile and if the caller score exceeds a certain threshold, an immediate alert is sent to the agent as pop-up message on his screen, instructing him to transfer the call to his supervisor as there is a suspicion. The supervisor receives all the relevant information on the caller profiler and past activity, so he can decide how to handle the call.

---

## 2.4 Investigation and Case Management

The EFMTT Investigation Center (IC) is a comprehensive platform which provides a complete framework for all activities within the entire fraud investigation life-cycle.

The IC is composed of a set of integrated functions, each deals with a different aspect of the fraud investigation process. Providing a user-friendly web-based user-interface, the IC enables investigators with no technical background to fully control the investigation environment and processes. It allows investigators to control business rules parameters and thresholds, set scoring calculation functions, maintain white and black lists, configure automatic case creation, define reports, etc.

The IC makes it possible for the investigator to view all information relevant to an alert, case or profile in one consolidated view with flexible drilldown options on each related entity.

### 2.4.1 Case Manager (Original EFMTT)

The Case Manager function enables the fraud investigation team to manage the organizational process of prioritizing and reviewing the alerts and cases. It allows the investigator to perform the investigation while capturing the case's information including relevant alerts, investigation activities performed, investigation notes, attachment files, and conclusions related to the investigation process. The Case Manager enables the organization to ensure methodical and well documented investigations. The case structure (type, status, association to other entities, etc.) is customizable according to the case type and organizational needs.

Alerts and cases can be displayed and sorted by their scores. The investigator may specify the score criteria for display, e.g. only alerts or cases with a score higher than 100.

### 2.4.2 Workflow Engine (Original EFMTT)

A Workflow Engine allows the organization to manage the investigation process in a methodical manner. The EFMTT IC can route cases based on different criteria, such as case-types or risk-classification. The criteria can be customized according to organizational requirements.

### 2.4.3 Unique Replay Capabilities (Original EFMTT)

One of the unique and powerful functions of EFMTT is Visual Replay of user activities screen by screen. It allows the investigator to go directly to the screens which triggered the investigated alert or case and scroll backward or forward to fully understand the actual user behavior and the context of his activities. This function enables the investigator to perform a thorough examination of the case in a simple and quick manner.

The captured screen demonstrates a mainframe session replay displayed to an auditor using EFMTT. In this example the twelfth screen of the user session is displayed. The fields changed by the user are marked in yellow. The auditor can also view the screen as it was originally displayed before the user input. The auditor can browse through the session scrolling to the next or previous screen.

User activity on Web applications may be replayed in a similar way. The monitored end-users may be the organization's employees using the internal Intranet applications or customers using the organization's Internet applications (e.g. Internet banking).

### 2.4.4 Cross-Platform Search of User Activity (Original EFMTT)

The investigator may search, for example, for all users who accessed a specific customer account in a specific timeframe. This search can be performed on recorded data from a specific platform (e.g. Web) or on data recorded from several platforms (e.g. Mainframe, Client/Server, Web, AS/400, database access, etc.).

### 2.4.5 Powerful Reporting Function (Original EFMTT)

The IC enables investigators to view all relevant information about an alert, case or profile in one consolidated view with flexible drilldown capabilities on each related entity. For example, when the investigator displays an alert or a case about a user who performs excessive activity on dormant accounts, he can easily point and click the account-id or user-id displayed on screen and the system immediately displays a consolidated view of all pertinent information collected on the relevant account and/or user.

The reports are based on a set of customizable pre-defined tables. The system enables definition of reports according to the organization needs. In each report the user can define the fields, predefined filters, input filters, sorting fields, etc. The reports can be displayed on screen or exported to PDF/Excel format. In addition the system facilitates integration with external tools for drilldown or extended reporting capabilities. Each report includes the ability to drilldown to a single field level.

### 2.4.6 Link Analysis (Original EFMTT)

The Link Analysis function is a powerful tool for uncovering fraud. It enables investigators to visually display relationships between various entities such as employees, customers, accounts, addresses, phone numbers, social security numbers, etc. Entities that are already under investigation or have been identified as fraudulent are highlighted with a background color allowing the investigator to examine suspicious relationships. The system allows the user to zoom-in and out, change the anchor, change the analysis depth, change the date range, drill-down to any entity, etc.

### 2.4.7 Live User Session Viewing (New in 2.0)

**Feature 38: Live User Session Viewing**

In addition to recorded replay, investigators can now watch ongoing user sessions in real time, enabling immediate intervention when suspicious activity is observed.

### 2.4.8 Remote Desktop Control (New in 2.0)

**Feature 17: Remote Desktop Control**

Investigators can take remote control of a user's desktop for troubleshooting or to directly intervene in suspicious activity.

### 2.4.9 Endpoint Isolation (New in 2.0)

**Feature 18: Endpoint Isolation**

Upon detection of a threat, the device can be isolated from the network to prevent further damage or data exfiltration.

### 2.4.10 Process Termination (New in 2.0)

**Feature 19: Process Termination**

Suspicious processes can be terminated remotely.

### 2.4.11 Rollback Capability (New in 2.0)

**Feature 20: Rollback Capability**

Systems can be restored to a known good state after an incident.

---

## 2.5 Data Loss Prevention and Active Blocking (New in 2.0)

### 2.5.1 Content-Aware DLP

**Feature 1: Content-Aware DLP**

EFMTT 2.0 now inspects file content, not just network traffic, to identify and block sensitive data based on what it actually contains. This enables precise detection of intellectual property, customer data, financial records, and other protected information.

### 2.5.2 USB Device Detection and Blocking

**Feature 2: USB Device Detection and Blocking**

The endpoint agent detects inserted USB devices and can block data transfers to unauthorized removable media, preventing one of the most common data exfiltration vectors.

### 2.5.3 Clipboard Monitoring

**Feature 3: Clipboard Monitoring**

Tracks data copied across applications, detecting when sensitive information is copied from a protected application to an unauthorized destination.

### 2.5.4 Cloud Upload Blocking

**Feature 4: Cloud Upload Blocking**

Prevents file uploads to personal cloud drives, GenAI tools, and other unauthorized cloud services.

### 2.5.5 Email Attachment Interception

**Feature 5: Email Attachment Interception**

Detects and blocks sensitive attachments before they are sent, scanning both content and context.

### 2.5.6 Print Control

**Feature 6: Print Control**

Tracks and restricts printing of sensitive documents, with full audit trail of print jobs.

### 2.5.7 Dynamic Policy Adjustment

**Feature 7: Dynamic Policy Adjustment**

Automatically tightens or relaxes DLP policies based on real-time user risk scores, ensuring that high-risk users face stricter controls without burdening low-risk users.

### 2.5.8 File Rename/Move Monitoring

**Feature 8: File Rename/Move Monitoring**

Detects abnormal renaming or moving of sensitive files, which may indicate attempts to disguise exfiltration.

### 2.5.9 Permission Change Auditing

**Feature 9: Permission Change Auditing**

Tracks modifications to file/folder sharing permissions, detecting attempts to grant unauthorized access.

### 2.5.10 Screenshot Blocking

**Feature 10: Screenshot Blocking**

Prevents users from capturing sensitive screen content via screenshot tools.

---

## 2.6 Real-Time Response and Automation (New in 2.0)

### 2.6.1 Real-Time User Blocking

**Feature 31: Real-Time User Blocking**

Immediately blocks user actions when suspicious activity occurs, preventing damage rather than merely recording it.

### 2.6.2 Automated Policy Enforcement

**Feature 32: Automated Policy Enforcement**

Automatically executes predefined policies when high-risk behavior triggers, without requiring human intervention.

### 2.6.3 Playbook Response

**Feature 33: Playbook Response**

Preset automated response workflows for downloads, uploads, email, printing, and other actions, ensuring consistent and rapid response.

### 2.6.4 SOAR Integration

**Feature 34: SOAR Integration**

Integration with Security Orchestration, Automation and Response platforms for enterprise-wide coordination.

### 2.6.5 Ticketing System Integration

**Feature 35: Ticketing System Integration**

Alerts automatically create tickets in existing ITSM platforms.

### 2.6.6 Email/SMS Alerts

**Feature 36: Email/SMS Alerts**

Real-time alerts pushed to email or SMS for immediate notification.

### 2.6.7 External System Triggering

**Feature 37: External System Triggering**

Triggers preset workflows in other systems via MQ/Web Service.

---

## 2.7 Identity and Access Management (New in 2.0)

### 2.7.1 Shared Account Authentication

**Feature 39: Shared Account Authentication**

Provides identity verification for shared logins, ensuring accountability even when accounts are shared.

### 2.7.2 Two-Factor Authentication Integration

**Feature 40: Two-Factor Authentication Integration**

Built-in 2FA support for enhanced access security.

### 2.7.3 One-Time Passwords

**Feature 41: One-Time Passwords**

Generates OTPs for privileged access, reducing risk of credential compromise.

### 2.7.4 Privileged Account Management

**Feature 42: Privileged Account Management**

Dedicated management of DBA, sysadmin, and other privileged account access.

### 2.7.5 Role-Based Access Control

**Feature 43: Role-Based Access Control (RBAC)**

Dashboard viewing permissions isolated by role, ensuring investigators only see what they need.

### 2.7.6 Active Directory Integration

**Feature 44: Active Directory Integration**

Integration with AD for unified identity management.

### 2.7.7 PAM Integration

**Feature 45: PAM Integration**

Integration with UNIX PAM modules.

### 2.7.8 Multi-Factor Anomalous Login Detection

**Feature 68: Multi-Factor Anomalous Login Detection**

Alerts when the same user logs in from different terminals simultaneously, indicating credential sharing or account takeover.

---

## 2.8 Compliance and Audit Support (New in 2.0)

### 2.8.1 GDPR Compliance Support

**Feature 46: GDPR Compliance Support**

Privacy protection features meeting GDPR requirements.

### 2.8.2 HIPAA Compliance Support

**Feature 47: HIPAA Compliance Support**

Healthcare data protection compliance.

### 2.8.3 PCI-DSS Compliance

**Feature 48: PCI-DSS Compliance**

Payment card industry compliance.

### 2.8.4 SOC 2 Type II

**Feature 49: SOC 2 Type II**

Security control audit certification.

### 2.8.5 CCPA Compliance

**Feature 50: CCPA Compliance**

California Consumer Privacy Act support.

### 2.8.6 FINRA Audit Support

**Feature 51: FINRA Audit Support**

Financial industry regulatory compliance.

### 2.8.7 Exportable Audit Logs

**Feature 52: Exportable Audit Logs**

Structured log export for compliance documentation.

### 2.8.8 Retention Policy Configuration

**Feature 53: Retention Policy Configuration**

Customizable data retention periods (e.g., 6-12 months online).

### 2.8.9 Data Archiving

**Feature 54: Data Archiving**

Automatic archiving of expired data.

---

## 2.9 Integration and Extensibility (New in 2.0)

### 2.9.1 SIEM Integration

**Feature 55: SIEM Integration**

Integration with Splunk, ArcSight, QRadar, and other SIEM platforms.

### 2.9.2 API Export

**Feature 56: API Export**

Data export to external systems via API.

### 2.9.3 CSV/PDF Export

**Feature 57: CSV/PDF Export**

Report export in common formats.

### 2.9.4 Project Management Tool Integration

**Feature 58: Project Management Tool Integration**

Integration with PM tools to identify workflow bottlenecks.

### 2.9.5 Custom Web/App Monitoring

**Feature 59: Custom Web/App Monitoring**

Enterprise edition supports custom application monitoring.

### 2.9.6 Geographic Productivity Comparison

**Feature 60: Geographic Productivity Comparison**

Compares productivity differences between office and remote work.

### 2.9.7 Instant Messaging Monitoring

**Feature 62: Instant Messaging Monitoring**

Tracks Teams, Slack, and other IM communications.

### 2.9.8 Social Media Monitoring

**Feature 63: Social Media Monitoring**

Monitors social media use for brand reputation protection.

### 2.9.9 Geolocation Tracking

**Feature 66: Geolocation Tracking**

Records device geographic location to identify anomalous logins.

### 2.9.10 Stealth Mode

**Feature 64: Stealth Mode**

Monitoring agent invisible in Task Manager.

### 2.9.11 Tamper-Proof Installation

**Feature 65: Tamper-Proof Installation**

Prevents regular users from detecting or uninstalling monitoring software.

---

## 3. EFMTT in Practice

EFMTT is utilized mainly for detecting and preventing fraud and for compliance with government regulations. Libraries of fraud scenarios and detection rules are provided for the areas listed below. These rules were developed by highly seasoned fraud practitioners and are based on customer experience.

- Employee Fraud
- Information Leakage
- Identity Theft
- Privileged IT User Monitoring
- ACH Fraud
- Check Kiting
- Account Takeover
- eBanking Fraud
- Phone Banking Fraud
- ATM Fraud
- Insurance Fraud
- Healthcare Fraud

The system can help comply with several government regulations:

- Anti-Money Laundering
- FACTA
- Identity Theft Red Flags
- GLBA, PCI and other privacy regulations which require a detailed audit trail of access to sensitive customer data
- Sarbanes-Oxley which requires effective internal controls for tracking financial processes

### 3.1 EFMTT for Retail Chains (Original)

Retail chains normally operate in a highly competitive market. Following are several examples of information that is very sensitive and must not be exposed to their competitors, suppliers and customers. This information should be accessed only by authorized people in the relevant departments. EFMTT can detect access by unauthorized user-ids or from terminals in non-related departments. The pattern of access (high volume, time of day, specific data profiles) may be also tracked as suspicious.

- **Buying quote** – the buying prices from different vendors, sensitive information that only purchasing department personnel should be exposed to.
- **Special campaign and promotions** – should be secured until due date and accessed only by very few people.
- **Salaries** – Should be accessed only by designated managers and specific people in the HR department.
- **Financial statements** – (for public companies) quarterly and yearly reports should be published on specific dates and should not be disclosed prior to these dates.

### 3.2 Operational Failures (Original)

EFMTT can detect events which may cause losses to the retailer. These events may be a result of intentional fraud or a result of non-intentional negligence. In some cases, the alert to the store manager should be sent as SMS to allow immediate action.

- Sell a product at a lower price than purchase price.
- Sell with abnormal discount.
- Shipping to customer with lower purchase amount than allowed.
- Selling in wholesale price for small quantity.
- Some products (such as candy) are positioned on the counter near the cashier to promote impulse purchase by customers at checkout. Sudden drop in sell of a specific product in a specific cashier may indicate that the product is missing on the stand near the cashier.
- New updated price that is not reflected in sell price.
- Receiving products back which are not allowed to be returned or products that are allowed but in large quantities.

### 3.3 Privileged Users Suspicious Activity (Original)

System administrators, DBAs and applications programmers typically have access to sensitive components of the system infrastructure and data. Following are several examples of suspicious actions by these privileged users which may be part of fraud schemes.

- Changing data in the production environment through a query tool (e.g. SQL/400, DB/2 SPUFI or QMF).
- Changing program code in the production environment.
- Changing sensitive data in the production environment using an application from a terminal in the IT department and/or with IT user-id.
- A scenario of moving a new program version to the production environment, executing it and moving another version to the production environment (covering traces).
- A scenario of moving a new program to the production environment, executing it and erasing it from the production environment (covering traces).
- Executing programs in the production environment.
- Login with a user-id of a business user from a terminal in the IT department after business hours or on weekends.
- Login with the same user-id from different terminals.
- Adding new fields to tables with sensitive data (it allows to copy data to the new field and extracting data from the new field, which may have a misleading name).

---

## 4. EFMTT Out-of-the-Box Implementation

EFMTT is unique in its ability to provide a very significant value out-of-the-box. Based on network sniffing it provides immediate audit trail upon product installation, which typically takes just a few hours with no need for customization, integration or business rule definitions. Upon out-of-the-box installation, EFMTT records all user activity on the designated servers and automatically builds indices for Google-like free-text search. The recorded activity can be replayed, analyzed, and reported. Since business rules can be applied to old recorded data after-the-fact, it is not necessary to define business rules upon system installation. The business rule definition can be performed at a later stage on an ongoing basis.

Implementing rules in EFMTT is significantly shorter than traditional fraud detection approach since there is no need for a long ETL project. The required data for the desired rules can be easily extracted from the relevant user screens in a matter of minutes using a simple and intuitive point-and-click user interface.

With EFMTT 2.0, endpoint agents can be deployed alongside network sensors, extending visibility to local activity while maintaining the same rapid deployment model.

---

## 5. System Scalability and Reliability

The EFMTT architecture is very flexible and scalable providing a cost-effective solution to organizations with 500 employees as well as corporations with 100,000 employees and more. EFMTT can be deployed in a wide range of configurations according to the organization structure and needs. EFMTT may be configured to support a central auditing and investigation group that audits all end users as well as decentralized groups of auditors and investigators, each monitoring a subset of the users.

The EFMTT sensors (sniffers) can be deployed in several data centers connected to one or more network switches in each data center. Each sensor server may listen to one or more protocols in one or more network switches. The sensors may be configured to send data to one or more analyzer servers. Analyzers may be deployed in one or more data centers analyzing data on the departmental/regional level and/or at the corporate level. Multiple analyzers can load balance the work among them, i.e. each analyzer handles part of the user sessions.

The analyzers may store the captured and analyzed data in databases deployed in a variety of configurations. A local database may be deployed in each data center allowing for searches on local activity. A central database may be deployed for storing user activity across all data centers. A combination of local databases and a central database may be used in order to allow both local searches and cross data center searches.

Recorded data from different platforms can be handled differently according to the auditing needs of the organization. For example, AS/400 recorded data can be stored only in local databases, while mainframe recorded data can be stored both in local and central databases.

Essential for capturing real-time network traffic, the EFMTT architecture is designed for high reliability. The Sensor server performs only the minimal processing of capturing and filtering the network packets, placing them on a queue for analysis by the Data Channel Analyzer. The different system components continuously check the queues and health of each other, to ensure that no data is being lost. Following are examples of SNMP alerts generated by the EFMTT analyzer when it detects that:

- The Sensor does not capture data from the switch for a period of predefined time
- The Analyzer detects that the queues are empty for a period of predefined time, which means that the Sensor is not operating
- The Backlog queue files exceed some threshold size
- The disk space available for the Recordings is smaller than a predefined threshold

---

## 6. Disk Space Requirements

EFMTT does not store the actual image (bitmap) of the user screens but rather stores the intercepted raw network transmission from which it reconstructs the user screens and keystrokes when needed; hence it is very efficient regarding disk space. The data is condensed at a ratio of 1:10. Based on the experience of EFMTT customers using 3270 based applications the recorded data of one end-user of one business day typically requires only about 50-60KB. So, for example, recording 10,000 end-users that use 3270 applications requires about 500-600MB for one day. If the data is stored for 6 months, then the disk space required is about 90GB. This estimate includes the recorded screens. In addition to the recorded data the EFMTT database stores formatted data including field values that were identified in the user screens. Depending on the amount of fields identified in the screens, the disk space required for this formatted data may be similar to the recorded data, so the total of required disk space for this example may be approximately 180 GB.

Tracking web based and client-server applications typically requires more disk space than 3270 applications. In the case of client-server messages, the amount of disk space required depends on the volume of traffic of the monitored applications. Similarly to screen recording (3270, 5250, HTML), in which the screen image is not stored, in client-server monitoring EFMTT does not store the screen bit map, but rather the raw network transmissions in a condensed format.

EFMTT customers typically store the recorded data for 6-12 months in online environment, after which the oldest data is sent to archive.

---

## 7. Security

As EFMTT captures highly sensitive data, its architecture was designed to protect the data and data access. EFMTT encrypts the recorded data and digitally signs it. The communication between the EFMTT servers is encrypted as well. Access to the EFMTT investigation tools is granted only to authorized and authenticated users (typically security officers and investigators), each user is assigned with specific access levels to specific data according to his role definitions.

EFMTT integrates with Active Directory when it runs under Windows or PAM (Pluggable Authentication Modules) when it runs under UNIX. Each user or user group defined in Active Directory or PAM may be assigned with permissions to access specific components within the system. EFMTT provides several permission types that can be assigned to different components and on different levels. Permissions are allowed or denied to individual users or user groups.

For forensic purposes, the system encrypts the recorded data (using 128 bit AES), and digitally signs it (using MD5 with RSA), so potentially it can be accepted as forensic evidence by courts. In several cases data from EFMTT has been used in US Federal and State courts proceedings.

---

## 8. Extracting Data from EFMTT

Data can be extracted from EFMTT in several ways:

- Data of User Activity Events can be written to an external database, to external files or be sent as a Web Service. This data may include any field from user screens, web pages, MQ message, and other objects that were captured in real-time.
- Rule Engine alerts may be sent as email or SMS or may be written to an external database, to external files, to an external queue (WebSphere MQ, JMS, MSMQ) or be sent as a Web Service.

---

## 9. The EFMTT Uniqueness

The EFMTT patent-pending technology is the only solution on the market that non-invasively records and analyzes end-user behavior at the application screen level in Mainframe, AS/400, Web and other platforms. Following are the EFMTT features that are not provided by other solutions:

- Recording end user activity (screens and keystrokes) in heterogeneous platforms including legacy systems.
- Visual replay of end-user screens and keystrokes at the application level.
- Analyzing the recorded screens and keystrokes and creating a configurable field-level audit trail of both update and read actions.
- Cross-platform Google-like search on user screen content allowing, for example, to search for all the users who accessed a specific account number in a specific timeframe in any application on Mainframe, AS/400, Web and other platforms.
- Tracking all end user actions including read-only transactions that do not leave any traces in the database. Tracking read-only transactions is very important for detecting information leakage and for compliance with privacy regulations. Most solutions have visibility only to updates made in the database not to read-only actions.
- Tracking the activity of all end users on legacy systems including privileged IT users such as systems administrators, database administrators and programmers.
- Real-time alerts based on data captured from the corporate network. Other solutions may have the analytic ability to provide real-time alerts, however information is typically provided to them offline (log files and databases), hence real-time alerts are actually not possible.
- EFMTT provides unique business value out-of-the-box – immediately following the installation EFMTT provides the functionality of record, replay and search with no need for time-consuming integration with any of the organization's systems or application-related configurations.
- Tracking suspicious events based on actual user screens and keystrokes, not just data that was updated in databases or logs as some solutions do.
- Since all user activity is recorded, EFMTT allows the internal auditor to apply new rules to recorded data after-the-fact.

**New in 2.0:**

- Endpoint agent deployment for local activity capture.
- Content-aware DLP with active blocking.
- Dynamic risk scoring with 150+ behavioral indicators.
- Predictive analytics and burnout/attrition risk analysis.
- Real-time user blocking and automated response workflows.
- SOAR, SIEM, and ticketing system integration.
- Comprehensive compliance support (GDPR, HIPAA, PCI-DSS, SOC 2, CCPA, FINRA).
- Remote desktop control, endpoint isolation, process termination, and rollback.
- Live user session viewing.
- Behavioral biometrics and synthetic data analytics.

---

## 10. Summary of All 68 New Features

| Category | Features |
|----------|----------|
| **Data Loss Prevention** | 1. Content-aware DLP · 2. USB blocking · 3. Clipboard monitoring · 4. Cloud upload blocking · 5. Email attachment interception · 6. Print control · 7. Dynamic policy adjustment · 8. File rename/move monitoring · 9. Permission change auditing · 10. Screenshot blocking |
| **Endpoint Monitoring** | 11. Endpoint agent deployment · 12. Process-level forensics · 13. File system change tracking · 14. Registry monitoring · 15. RDP session recording · 16. Citrix monitoring · 17. Remote desktop control · 18. Endpoint isolation · 19. Process termination · 20. Rollback capability |
| **Behavioral Analytics** | 21. Dynamic risk scoring · 22. 150+ behavioral indicators · 23. Predictive analytics · 24. Burnout/attrition risk · 25. Active vs idle distinction · 26. Automatic behavior baseline · 27. Cross-channel correlation · 28. Behavioral biometrics · 29. Synthetic data analytics · 30. Sentiment analysis |
| **Real-Time Response** | 31. Real-time user blocking · 32. Automated policy enforcement · 33. Playbook response · 34. SOAR integration · 35. Ticketing integration · 36. Email/SMS alerts · 37. External system triggering · 38. Live session viewing |
| **Identity & Access** | 39. Shared account authentication · 40. 2FA integration · 41. One-time passwords · 42. Privileged account management · 43. RBAC · 44. AD integration · 45. PAM integration |
| **Compliance** | 46. GDPR · 47. HIPAA · 48. PCI-DSS · 49. SOC 2 Type II · 50. CCPA · 51. FINRA · 52. Exportable audit logs · 53. Retention policy config · 54. Data archiving |
| **Integration** | 55. SIEM integration · 56. API export · 57. CSV/PDF export · 58. PM tool integration · 59. Custom app monitoring · 60. Geographic productivity comparison |
| **Additional** | 61. OCR · 62. IM monitoring · 63. Social media monitoring · 64. Stealth mode · 65. Tamper-proof install · 66. Geolocation tracking · 67. Incognito monitoring · 68. Multi-factor anomalous login detection |

---

## 11. The EFMTT 2.0 Advantage

EFMTT 2.0 combines the original platform's unique strengths — non-invasive network capture, visual replay, cross-platform search, and retrospective rule application — with modern capabilities that competing solutions offer separately.

**The result is a single platform that:**

1. **Records everything** — network traffic, endpoint activity, file operations, communications
2. **Analyzes everything** — free-text search, OCR, behavioral analytics, predictive scoring
3. **Blocks threats** — DLP, USB blocking, cloud upload prevention, real-time user blocking
4. **Responds automatically** — playbooks, isolation, termination, rollback
5. **Integrates seamlessly** — SIEM, SOAR, ticketing, AD, PAM, API
6. **Complies comprehensively** — GDPR, HIPAA, PCI-DSS, SOC 2, CCPA, FINRA

**All Rights Reserved. Distribution of this document requires explicit permission from:**

**Mascall Investments Private Ltd**
*Your Ultimate Solutions to Improved Controls, Risk Management & Governance*


Based on the search results, several features appear in other insider risk and forensic monitoring platforms that are **not present in the EFMTT 2.0 document** you shared.

### 🆕 Newly Identified Features Not in EFMTT 2.0

| **Category** | **Feature** | **Description & Platform Source** |
| :--- | :--- | :--- |
| **File & Data Monitoring** | **File Activity & Exfiltration Monitoring** | Tracks files downloaded via browser, copied to cloud sync folders (e.g., OneDrive, Dropbox), or transferred to USB devices. ObserveIT provides this capability . |
| | **Email Attachment & Content Monitoring** | Monitors emails sent from clients, including attachments, to detect data exfiltration. ObserveIT and Teramind offer this . |
| **Content & Analytics** | **Website Categorization** | Automatically classifies websites (e.g., gaming, adult, malicious, phishing) to generate alerts on browsing behavior. ObserveIT provides 42 out-of-box categories . |
| | **Network Traffic Analysis** | Monitors network activity to identify threats and optimize performance, distinct from application-level capture. Teramind provides this . |
| **Response & Enforcement** | **Forcible Logoff / Application Closure** | Remotely logs a user off an unauthorized machine or closes harmful applications. ObserveIT offers this as a prevention capability . |
| | **Linux Command Prevention** | Prevents malicious or unauthorized Linux commands from being executed. ObserveIT offers this . |
| **User Behavior & Risk** | **User Anonymization / Privacy Mode** | Protects user privacy by anonymizing personal information in dashboards and consoles. ObserveIT provides this . |
| | **Out-of-Policy User Notifications** | Displays warnings to users when they violate policy, aiming to educate and change behavior. ObserveIT and Teramind offer this . |
| | **Insider Threat Library (Pre-built Rules)** | Provides an extensive library of pre-configured alert rules based on NIST, MITRE, CERT guidelines. ObserveIT has 320+ indicators . |

### 💡 Key Takeaways

*   **Scope of Data Capture**: EFMTT 2.0 already includes File System Change Tracking (Feature 13) and Email Attachment Interception (Feature 5) for blocking. However, the new findings emphasize **monitoring the movement of files to external destinations** (like cloud sync folders) and **content-level email inspection**, which are distinct from simply blocking or tracking local changes.
*   **Behavioral Education**: Features like **Out-of-Policy User Notifications** and the **Insider Threat Library** represent a shift from pure detection to **proactive user education and standardization** based on industry frameworks (NIST, MITRE).
*   **Privacy & Legal**: **User Anonymization** is a critical feature for deployments where privacy regulations or works councils require that analysts don't see personal identifiers, a consideration not mentioned in the EFMTT 2.0 document.

In summary, while EFMTT 2.0 covers a very broad set of functions, other platforms excel at **monitoring data in transit to specific external destinations**, **educating users in real-time**, and **preventing specific OS-level actions** (like Linux commands).

Would you like me to help you integrate any of these specific features into your documentation?