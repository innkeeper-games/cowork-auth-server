from handler import Handler
from settings_database_connector import SettingsDatabaseConnector

import json
from uuid import uuid4
import logging

# key is type, value is dictionary of requirements and types
message_templates = {
    "request_room": {"type": "request_room", "room_id": str},
}

class PublicHandler(Handler):

    def __init__(self, authentication_handler):
        self.authentication_handler = authentication_handler
        self.public_database_connector = SettingsDatabaseConnector()


    def is_valid(self, message):
        global message_templates
            
        return Handler.is_valid(self, message_templates, message)


    async def consumer(self, websocket, message):
        message_valid = self.is_valid(message)
        if message_valid:
            await getattr(self, message["type"])(websocket, message)
        else:
            logging.error(
                "Message type is " + message["type"] + " " + str(message))
            logging.error(
                str(message_valid))


    async def request_room(self, websocket, message):
        # if the room is public, respond with basic information about the room
        response = {}
        if self.public_database_connector.room_exists(message["room_id"]):
            if not self.public_database_connector.get_room_privacy(message["room_id"]):
                title = self.public_database_connector.get_room_title(message["room_id"])
                description = self.public_database_connector.get_room_description(message["room_id"])
                member_count = len(self.public_database_connector.get_room_members(message["room_id"]))
                response = {"channel": "public", "type": "request_room", "title": title, "description": description, "member_count": member_count}
            else:
                response = {"channel": "public", "type": "request_room", "title": None, "member_count": None}
        else:
            response = {"channel": "public", "type": "request_room", "title": None, "member_count": None}
        response_json = json.dumps(response)
        await websocket.send(response_json)