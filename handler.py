from abc import ABC, abstractmethod

class Handler(ABC):

    def is_valid(self, message_templates, message):
        valid = False
        
        if message["type"]:
            requirements = list(message_templates[message["type"]].keys())[1:]
            num_requirements = len(requirements)
            num_requirements_met = 0
            for requirement in requirements:
                if requirement in message:
                    if type(message[requirement]) == message_templates[message["type"]][requirement]:
                        num_requirements_met += 1
            if num_requirements_met == num_requirements:
                valid = True
            
        return valid

    @abstractmethod
    async def consumer(self, websocket, message):
        pass
