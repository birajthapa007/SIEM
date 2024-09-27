# Configuration settings for the SIEM system
class Config:
    DATABASE_PATH = 'siem.db'
    LOG_FILE_PATH = 'C:/Users/shake/OneDrive/Desktop/SIEMProject/sample_log.log'
    LOG_FORMAT = r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[(?P<event_type>\w+)\]\s+(?P<description>.+)'
    ALERT_KEYWORDS = ['error', 'failure', 'critical']
