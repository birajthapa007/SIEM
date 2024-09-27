import re
from config import Config

class LogParser:
    def parse(self, line):
        match = re.search(Config.LOG_FORMAT, line)
        if match:
            return match.groupdict()
        return None
