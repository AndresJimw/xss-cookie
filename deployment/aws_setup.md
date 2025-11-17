# AWS EC2 setup for xss-cookie-lab

## 1. Create the EC2 instance

- AMI: Ubuntu Server 22.04 LTS
- Instance type: t2.micro (or similar)
- Key pair: choose or create one
- Security group:
  - Allow SSH (port 22) from your IP.
  - Allow HTTP (port 5000) from your IP or from 0.0.0.0/0 as required for the demo.

## 2. Connect via SSH

```bash
ssh -i /path/to/your-key.pem ubuntu@<ec2-public-ip>
