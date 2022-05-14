import accounts

import os

from handler import Handler
from emailer import Emailer

import json
from uuid import uuid4
from secrets import token_urlsafe
import logging
import re

EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")

# key is type, value is dictionary of requirements and types
message_templates = {
    "register_server": {"type": "register_server", "api_key": str},
    "get_session": {"type": "get_session", "token": str},

    "sign_up": {"type": "sign_up", "username": str, "password": str},
    "sign_in": {"type": "sign_in", "username": str, "password": str},
    "sign_out": {"type": "sign_out"},
    "request_reset_password": {"type": "request_reset_password", "username": str},
    "update_password": {"type": "update_password", "token": str, "password": str},
    "pong": {"type": "pong"}
}

class AuthenticationHandler(Handler):

    def __init__(self, scheduler, sign_up_enabled=True):
        self.auth_api_key = os.environ.get("COWORK_AUTH_API_KEY")
        self.servers = {}

        self.auth_database_connector = accounts.AccountsDatabaseConnector()
        self.unclaimed_tokens = set()
        self.tokens = {}
        self.usernames = {}
        self.authenticated_tokens = {}
        self.emailer = Emailer()
        self.reset_password_tokens = {}
        self.scheduler = scheduler
        self.sign_up_enabled = sign_up_enabled


    def is_valid(self, message):
        global message_templates
            
        return Handler.is_valid(self, message_templates, message)


    async def consumer(self, websocket, message):
        if (self.is_valid(message)):
            if message["type"] == "register_server":
                await self.register_server(websocket, message)
            elif message["type"] == "get_session":
                await self.get_session(websocket, message)
            elif message["type"] == "removed_client":
                await self.removed_client(websocket)

            elif message["type"] == "sign_up":
                await self.sign_up(websocket, message)
            elif message["type"] == "sign_in":
                await self.sign_in(websocket, message)
            elif message["type"] == "sign_out":
                await self.sign_out(websocket)
            elif message["type"] == "request_reset_password":
                await self.request_reset_password(websocket, message)
            elif message["type"] == "update_password":
                await self.update_password(websocket, message)
            elif message["type"] == "pong":
                await self.pong(websocket)
            else:
                logging.error(
                    "Message type is " + message["type"] + " " + str(message))


    async def remove_peer(self, websocket):
        if websocket in self.servers:
            print("De-registering the server at " + str(websocket))
            self.servers.pop(websocket)


    async def register_server(self, websocket, message):
        api_key = message["api_key"]
        response = {"channel": "auth", "type": "register_server", "success": False}
        if api_key == self.auth_api_key:
            self.servers[websocket] = 0
            response = {"channel": "auth", "type": "register_server", "success": True}
        response_json = json.dumps(response, default=str)
        await websocket.send(response_json)


    async def is_server(self, websocket):
        return websocket in self.servers


    def get_a_server(self):
        mininum_clients_server = list(self.servers.keys())[0]
        for server in self.servers:
            if self.servers[server] < self.servers[mininum_clients_server]:
                mininum_clients_server = server
        return server


    def add_peer_to_server(self, server):
        self.servers[server] = self.servers[server] + 1
        print("Server " + str(server.remote_address[0]) + " now has " + str(self.servers[server] + " clients."))


    async def pong(self, websocket):
        response = {"channel": "auth", "type": "ping"}
        response_json = json.dumps(response, default=str)
        await self.scheduler.run()
        await websocket.send(response_json)


    async def get_session(self, websocket, message):
        if await self.is_server(websocket):
            token = message["token"]
            username = None
            if self.validate_token(token):
                username = self.usernames[self.authenticated_tokens[token]]
            if username is not None:
                response = {"channel": "auth", "type": "get_session", "token": token, "success": True, "username": username}
            else:
                response = {"channel": "auth", "type": "get_session", "token": token, "success": False}
            response_json = json.dumps(response, default=str)
            await websocket.send(response_json)


    async def removed_client(self, websocket):
        if await self.is_server(websocket):
            self.servers[websocket] = self.servers[websocket] - 1
            print("Server " + str(server.remote_address[0]) + " now has " + str(self.servers[server] + " clients."))


    async def sign_in(self, websocket, message):
        username = message["username"].lower()
        password = message["password"]
        if self.auth_database_connector.get(username) is not None:
            # convert the list to its string representation
            if self.auth_database_connector.verify(username, str(password)):
                account_id = self.auth_database_connector.get_id_for_username(username)
                self.make_session(websocket, username, account_id)
                response = {"channel": "auth", "type": "sign_in", "username": self.usernames[websocket], "account_id": account_id, "display_name": self.auth_database_connector.get_display_name_for_id(account_id), "username_exists": True, "password_correct": True}
            else:
                response = {"channel": "auth", "type": "sign_in", "username_exists": True, "password_correct": False, "error": "That password is incorrect."}
        else:
            response = {"channel": "auth", "type": "sign_in", "username_exists": False, "password_correct": False}
        response_json = json.dumps(response, default=str)
        await websocket.send(response_json)


    async def sign_up(self, websocket, message):
        response = {}
        if self.sign_up_enabled:
            username = message["username"].lower()
            password = message["password"]
            if not EMAIL_REGEX.match(username):
                response = {"channel": "auth", "type": "sign_up", "username_exists": False, "password_correct": False, "error": "Usernames must be valid email addresses."}
            elif len(username) < 4:
                response = {"channel": "auth", "type": "sign_up", "username_exists": False, "password_correct": False, "error": "Usernames must be more than 4 characters."}
            elif self.auth_database_connector.get(username) is None:
                self.auth_database_connector.complete_referrals(username)
                self.auth_database_connector.save(username, str(password))
                account_id = self.auth_database_connector.get_id_for_username(username)
                display_name = self.auth_database_connector.get_display_name_for_id(account_id)
                self.emailer.add_to_marketing_list(username, display_name)
                self.make_session(websocket, username, account_id)
                response = {"channel": "auth", "type": "sign_up", "username": self.usernames[websocket], "account_id": account_id, "display_name": display_name, "account_creation_success": True}
            else:
                response = {"channel": "auth", "type": "sign_up", "account_creation_success": False}
        else:
            response = {"channel": "auth", "type": "sign_up", "account_creation_success": False, "error": "Sign up is currently disabled."}
        response_json = json.dumps(response, default=str)
        await websocket.send(response_json)
    

    def make_session(self, websocket, username, account_id):
        self.authenticated_tokens[self.tokens[websocket]] = websocket
        self.usernames[websocket] = username


    async def sign_out(self, websocket):        
        if self.validate_session(websocket):
            print("Signing out " + str(websocket))
            token = self.tokens[websocket]
            self.authenticated_tokens.pop(token, None)
        response = {"channel": "auth", "type": "sign_out", "success": True}
        response_json = json.dumps(response, default=str)
        await websocket.send(response_json)


    async def request_reset_password(self, websocket, message):
        username = message["username"].lower()
        if self.auth_database_connector.get(username) is not None:
            id_ = token_urlsafe(8)
            self.reset_password_tokens[id_] = username
            self.emailer.send_reset_password(username, id_)
            self.scheduler.create_task(self.invalidate_reset_password_token, 86400, id_)
        response = {"channel": "auth", "type": "request_reset_password", "success": True}
        response_json = json.dumps(response, default=str)
        await websocket.send(response_json)



    def invalidate_reset_password_token(self, token):
        self.reset_password_tokens.pop(token)


    async def update_password(self, websocket, message):
        id_ = message["token"]
        if id_ in self.reset_password_tokens:
            username = self.reset_password_tokens[id_]
            password = message["password"]
            self.auth_database_connector.update_password(username, str(password))
            account_id = self.auth_database_connector.get_id_for_username(username)
            self.make_session(websocket, username, account_id)
            self.reset_password_tokens.pop(id_)
            response = {"channel": "auth", "type": "sign_in", "username": self.usernames[websocket], "account_id": account_id, "display_name": self.auth_database_connector.get_display_name_for_id(account_id), "username_exists": True, "password_correct": True}
            response_json = json.dumps(response, default=str)
            await websocket.send(response_json)


    def validate_session(self, websocket):
        if websocket in self.tokens:
            token = self.tokens[websocket]
            if token in self.authenticated_tokens:
                return True
        return False
    

    def validate_token(self, token):
        return token in self.authenticated_tokens
        
    
    def token_exists(self, token):
        return token in self.unclaimed_tokens


    def client_has_token(self, websocket):
        return websocket in self.tokens


    def add_client(self, websocket, token):
        if token in self.authenticated_tokens:
            # TODO: terminate the old connection? For now, we just invalidate it
            old_websocket = self.authenticated_tokens[token]

            self.authenticated_tokens[token] = websocket
            self.tokens[websocket] = token
            self.usernames[websocket] = self.usernames[old_websocket]

            self.usernames.pop(old_websocket)
        else:
            self.tokens[websocket] = token
        return self.tokens[websocket]


    def make_token(self):
        token = self.auth_database_connector.make_token()
        self.unclaimed_tokens.add(token)
        return token


    def remove_client(self, websocket):
        return self.tokens.pop(websocket, None)
    
