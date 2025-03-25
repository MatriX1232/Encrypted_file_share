class Logger:
    def __init__(self, name: str):
        self.colors = {
            "info": "\033[94m",  # Blue
            "success": "\033[92m",  # Green
            "warning": "\033[93m",  # Yellow
            "error": "\033[91m",  # Red
            "endc": "\033[0m"  # Reset color
        }
        self.name = name

    def info(self, message: str):
        print(f"{self.colors['info']}[INFO] [{self.name}] {message}{self.colors['endc']}")

    def success(self, message: str):
        print(f"{self.colors['success']}[SUCCESS] [{self.name}] {message}{self.colors['endc']}")

    def warning(self, message: str):
        print(f"{self.colors['warning']}[WARNING] [{self.name}] {message}{self.colors['endc']}")

    def error(self, message: str):
        print(f"{self.colors['error']}[ERROR] [{self.name}] {message}{self.colors['endc']}")
