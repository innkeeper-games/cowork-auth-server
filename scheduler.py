from datetime import datetime, timedelta


class Scheduler:
    
    def __init__(self):
        self.tasks = {}
    

    def create_task(self, coro, delta_seconds, *args):
        time = datetime.now() + timedelta(seconds=delta_seconds)
        # TODO
        while time in self.tasks:
            time = time + timedelta(microseconds=1)
        self.tasks[time] = [coro, args]
    

    async def run(self):
        for time in list(self.tasks):
            if datetime.now() > time:
                task = self.tasks.pop(time)
                await task[0](*task[1])