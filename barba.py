from serial import Serial

class Barba:
    def __init__(self):
        self.serial = Serial()
        self.serial.open()
        self.serial.write('Hello, Barba!')

    def __del__(self):
        self.serial.close()

    def helloworld(self):
        return self.serial.read()

print(Barba().helloworld())
