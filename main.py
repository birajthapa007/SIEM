from event_manager import EventManager
from config import Config

def main():
    manager = EventManager(Config.DATABASE_PATH)
    manager.process_logs(Config.LOG_FILE_PATH)

if __name__ == '__main__':
    main()
