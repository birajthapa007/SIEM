from config import Config

class AlertManager:
    def __init__(self, database):
        self.database = database

    def check_alerts(self, event):
        for keyword in Config.ALERT_KEYWORDS:
            if keyword in event['description'].lower():
                print(f"Alert: {keyword} found in event:", event)
