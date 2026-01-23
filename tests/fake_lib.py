# Simulating a 3rd party library
class Widget:
    def __init__(self, name, size):
        self.name = name
        self.size = size

    def run(self):
        return f"{self.name} running"

def factory():
    return Widget("factory_made", 10)
