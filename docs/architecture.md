# AI-SIEM Architecture

AI-SIEM is designed as a lightweight full-stack SOC/SIEM platform.

## Components

- **Frontend**: static HTML/CSS/JavaScript dashboard.
- **Backend**: Python standard-library HTTP API.
- **Data Layer**: JSON demo logs.
- **Detection Content**: YAML-like detection rules.
- **Parsers**: source-specific parser metadata.
- **Dashboards**: dashboard metadata definitions.
- **Workflows**: response playbooks.

## Data Flow

```text
sample_logs.json
  -> parser logic
  -> detection logic
  -> alert generation
  -> incident correlation
  -> triage API
  -> frontend dashboard
```

## API Flow

The frontend fetches backend endpoints every 15 seconds and updates the SOC dashboard.

## Design Goal

The goal is to demonstrate practical SOC engineering skills without requiring a complex stack.
