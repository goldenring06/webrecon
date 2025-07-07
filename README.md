# Ultimate Recon Tool

A next-generation reconnaissance tool with automated payload selection and intelligent scanning.

## ✨ Features
- Automated subdomain discovery
- Smart payload selection
- Historical data analysis (Wayback Machine, SecurityTrails)
- JavaScript secrets scanning
- Integrated directory brute-forcing

## 📦 Installation

git clone https://github.com/goldenring06/webrecon.git

# Set API tokens (required)
export GITHUB_TOKEN="ghp_yourtokenhere"
export SECURITYTRAILS_TOKEN="yourkeyhere"

# Build 
go build -o recon recon.go

# Run
./recon
