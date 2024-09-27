from database import Database
from log_parser import LogParser
from alert_manager import AlertManager

class EventManager:
    def __init__(self, db_path):
        self.database = Database(db_path)
        self.parser = LogParser()
        self.alert_manager = AlertManager(self.database)

    def process_logs(self, log_path):
        self.database.connect()
        with open(log_path, 'r') as file:
            for line in file:
                event = self.parser.parse(line)
                if event:
                    self.database.execute('''
                        INSERT INTO events (timestamp, event_type, description)
                        VALUES (:timestamp, :event_type, :description)
                    ''', event)
                    self.alert_manager.check_alerts(event)
        self.database.close()
