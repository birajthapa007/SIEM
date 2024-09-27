
# SIEM Project

This project is a basic **Security Information and Event Management (SIEM)** system designed to process log files, detect specific events, and trigger alerts based on customizable keywords. It is built using Python and SQLite for database management.

## Features
- Parses logs based on a configurable log format.
- Stores log events in a SQLite database.
- Triggers alerts for specific keywords (e.g., `error`, `failure`, `critical`).
- Easily configurable via `config.py`.

## Project Structure

```
SIEM-Project/
│
├── alert_manager.py     # Manages alerts when specific events are detected.
├── config.py            # Contains configuration settings for database, logs, and alerts.
├── database.py          # Handles database connection and event storage.
├── event_manager.py     # Manages log processing and interaction with other components.
├── log_parser.py        # Parses the log files based on the format specified in config.
├── main.py              # Entry point of the application to process logs.
├── sample_log.log       # Example log file used for testing the system.
└── README.md            # Project documentation.
```

## Requirements

To run this project, you will need:

- **Python 3.x**: You can download Python [here](https://www.python.org/downloads/).
- **SQLite**: SQLite is used for the database (no additional setup required).

Additionally, install the required Python packages via `pip`:


## How to Set Up

1. **Clone the repository** to your local machine:
   ```bash
   git clone https://github.com/birajthapa007/SIEM.git
   cd SIEM-Project
   ```

2. **Configure the project** by editing the `config.py` file:
   - **Database path**: Path to the SQLite database (`DATABASE_PATH`).
   - **Log file path**: Path to the log file that will be processed (`LOG_FILE_PATH`).
   - **Log format**: Customize the regex pattern used to parse logs (`LOG_FORMAT`).
   - **Alert keywords**: List of keywords that will trigger alerts (`ALERT_KEYWORDS`).

Example `config.py`:

```python
class Config:
    DATABASE_PATH = 'siem.db'
    LOG_FILE_PATH = 'C:/path/to/your/logfile.log'
    LOG_FORMAT = r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[(?P<event_type>\w+)\]\s+(?P<description>.+)'
    ALERT_KEYWORDS = ['error', 'failure', 'critical']
```

## How to Run

1. **Prepare the environment**: Ensure Python 3.x is installed and the required packages are available (SQLite is built-in).
2. **Run the main program** to process logs and trigger alerts:
   ```bash
   python main.py
   ```

## Log File Format

The system expects log files to follow a specific format, which can be customized in `config.py`. For example, the expected format might look like this:

```plaintext
2023-10-01 12:00:00 [ERROR] Failed to connect to the database.
2023-10-01 12:05:00 [INFO] System startup complete.
```

## How to Test

1. **Add a sample log file**: You can use the provided `sample_log.log` file or create your own log file with entries following the format.
2. **Run the project** and monitor console output for alerts triggered by specific log entries.

## Known Issues

- Ensure that the log file exists and is accessible at the path defined in `config.py`.
- For large log files, you may need to optimize the event processing or parse logs in chunks.

## Future Improvements

- Add support for real-time log processing.
- Integrate more robust alerting systems (email, Slack, etc.).
- Implement web-based dashboards for monitoring log events.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Feel free to submit pull requests, open issues, or suggest enhancements to improve the system.
