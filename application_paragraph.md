# Application Paragraph for Sticker Mule (AI Agent Engineer / Software Engineer)

---

### Short Version (for application form / cover letter)

I developed a lightweight Endpoint Detection and Response (EDR) prototype as an autonomous agent using FastAPI. The system continuously monitors endpoint and network logs collected via Winlogbeat and Packetbeat, normalizes the data, runs anomaly detection using an ensemble of CNN and Random Forest models, prioritizes threats, and indexes results into Elasticsearch. The agent also handles log rotation, real-time tailing, and serves a web dashboard. Although the original trained model weights were lost after a system failure, the complete agent architecture, data pipeline, and inference structure are fully documented and available in my GitHub repository. This project demonstrates my ability to design and implement agent-style systems that combine real-time data processing, machine learning, and production-ready APIs.

---

### Slightly Longer Version (if they ask for more detail)

During my final year project at the Air Force Institute of Technology, I designed and built a lightweight EDR agent focused on efficient threat detection and prioritization. The system is built around a FastAPI application that acts as a continuous monitoring agent. It dynamically discovers and tails log files from Winlogbeat (endpoint/Sysmon events) and Packetbeat (network traffic), normalizes heterogeneous log formats, and runs anomaly scoring using multiple machine learning models (CNN for endpoint behavior and Random Forest for network flows). Detected threats are indexed into Elasticsearch and exposed through clean API endpoints for a frontend dashboard. The agent also manages log rotation and cleanup in the background. While the original trained model files were lost after a system crash, the full architecture, processing pipeline, and agent design remain intact and are publicly documented. I am particularly interested in the AI Agent Engineer role because this project gave me hands-on experience building autonomous systems that combine real-time data ingestion, ML inference, and service-oriented architecture — skills I am eager to apply and grow at Sticker Mule.
