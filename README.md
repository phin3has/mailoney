# Mailoney

A Simple SMTP Honeypot with database logging.

## About

Mailoney is a low-interaction SMTP honeypot designed to detect and capture credentials from login attempts and potential SMTP abuse. This version uses database logging (PostgreSQL by default) to store all interactions and captured credentials.

## Features

- Simulates a basic SMTP server
- Captures and logs authentication credentials
- Stores all session data in a database
- Dockerized for easy deployment
- Modern Python package structure

## Installation

### Using Docker (Recommended)

The easiest way to run Mailoney is using Docker Compose:

```bash
# Clone the repository
git clone https://github.com/yourusername/mailoney.git
cd mailoney

# Start the services
docker-compose up -d
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/mailoney.git
cd mailoney

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package in development mode
pip install -e .

# Run Mailoney
python main.py
```

## Configuration

Mailoney can be configured using command-line arguments or environment variables:

### Command-line Arguments

- `-i`, `--ip`: IP address to bind to (default: 0.0.0.0)
- `-p`, `--port`: Port to listen on (default: 25)
- `-s`, `--server-name`: Server name to display in SMTP responses
- `-d`, `--db-url`: Database URL (default: sqlite:///mailoney.db)
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

### Environment Variables

- `MAILONEY_BIND_IP`: IP address to bind to
- `MAILONEY_BIND_PORT`: Port to listen on
- `MAILONEY_SERVER_NAME`: Server name to display in SMTP responses
- `MAILONEY_DB_URL`: Database URL
- `MAILONEY_LOG_LEVEL`: Logging level

## Database Configuration

By default, Mailoney uses SQLite for simplicity, but PostgreSQL is recommended for production use:

### PostgreSQL Connection String

```
postgresql://username:password@hostname:port/database
```

For example:

```
postgresql://postgres:postgres@localhost:5432/mailoney
```

## Database Schema

Mailoney creates two main tables:

1. `smtp_sessions`: Stores information about each SMTP session
   - `id`: Primary key
   - `timestamp`: When the session started
   - `ip_address`: Client IP address
   - `port`: Client port
   - `server_name`: Server name used
   - `session_data`: JSON data containing the full session log

2. `credentials`: Stores captured authentication credentials
   - `id`: Primary key
   - `timestamp`: When the credential was captured
   - `session_id`: Foreign key to the session
   - `auth_string`: The captured authentication string

## Development

### Running Tests

```bash
# Install development dependencies
pip install pytest pytest-cov

# Run tests
pytest
```

### Database Migrations

```bash
# Create a new migration
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head
```

## Docker Hub

The Docker image is automatically built and pushed to Docker Hub when changes are pushed to the main branch. You can pull the latest image with:

```bash
docker pull yourusername/mailoney:latest
```

## Project Structure

```
mailoney/
├── mailoney/            # Main package
│   ├── __init__.py      # Package initialization  
│   ├── core.py          # Core server functionality
│   ├── db.py            # Database handling
│   ├── config.py        # Configuration management
│   └── migrations/      # Database migrations
├── tests/               # Test suite
├── main.py              # Clean entry point
├── docker-compose.yml   # Docker Compose configuration
├── Dockerfile           # Docker configuration
├── pyproject.toml       # Package configuration
├── requirements.txt     # Dependencies
└── README.md            # Documentation
```

## License

MIT License

## Acknowledgments

This project is a modernized rewrite of the original Mailoney by @awhitehatter.
