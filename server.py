# Handles JSON messages and starts the authentication server

import os

from pathlib import Path
from http.cookies import SimpleCookie

import asyncio
import logging

import ssl
import websockets, websockets.http
from http import HTTPStatus

from aiohttp import web
import aiohttp_cors

import json

import accounts

from scheduler import Scheduler

from authentication_handler import AuthenticationHandler
from public_handler import PublicHandler

websocket_peers = set()

authenticated_peers = set()

scheduler = Scheduler()

authentication_handler = AuthenticationHandler(scheduler)
public_handler = PublicHandler(authentication_handler)

channels = {
    "auth": authentication_handler, "public": public_handler
}


async def hello(request):
    response = web.Response(text="A little sugar for you :)")
    if "token" in request.cookies:
        if channels["auth"].token_exists(request.cookies["token"]):
            return response
    response.set_cookie("token", authentication_handler.make_token(), secure=True, httponly=True, domain="ws.joincowork.com")
    return response


def add_websocket(websocket):
    global websocket_peers

    print("New peer connected to the authentication server.")
    websocket_peers.add(websocket)


async def remove_websocket(websocket):
    global websocket_peers

    print("A peer disconnected from the authentication server.")
    await channels["auth"].remove_peer(websocket)
    websocket_peers.remove(websocket)


async def consumer(websocket, message):
    global channels

    if "channel" in message:
        if message["channel"] in channels:
            if "type" in message:
                if message["channel"] == "auth" or message["channel"] == "public":
                    await channels[message["channel"]].consumer(websocket, message)
                else:
                    response = {"type": "sign_in", "username_exists": False, "password_correct": False}
                    response_json = json.dumps(response)
                    await websocket.send(response_json)
        else:
            print("There's no valid channel indicated; I cannot route the message.")
    return


async def consumer_handler(websocket, path):
    global channels

    add_websocket(websocket)
    if not websocket in authenticated_peers:
        if "cookie" in websocket.request_headers:
            cookies = websocket.request_headers["Cookie"]
            token = cookies[6:]
            if channels["auth"].token_exists(token):
                if not channels["auth"].client_has_token(websocket):
                    channels["auth"].add_client(websocket, token)
                if channels["auth"].validate_token(token):
                    authenticated_peers.add(websocket)
                    username = channels["auth"].usernames[websocket]
                    account_id = channels["auth"].auth_database_connector.get_id_for_username(username)
                    display_name = channels["auth"].auth_database_connector.get_display_name_for_id(account_id)
                    pro = channels["auth"].auth_database_connector.get_pro(account_id)
                    update_notes = channels["auth"].auth_database_connector.get_update_notes(account_id)
                    channels["auth"].auth_database_connector.update_last_login(account_id)
                    server = channels["auth"].get_a_server()
                    print("Assigning " + str(websocket.remote_address[0]) + " to server " + str(server.remote_address[0]))
                    response = {"channel": "auth", "type": "sign_in", "username": username, "account_id": account_id, "display_name": display_name, \
                        "username_exists": True, "password_correct": True, "update_notes": update_notes, "pro": pro, "server_ip": server.remote_address[0]}
                    response_json = json.dumps(response)
                    await websocket.send(response_json)
                    print("Closing the connection with " + str(websocket.remote_address))
                    await websocket.close()
        else:
            print("No cookies were shared.")
            print(websocket.request_headers)
    try:
        async for message_json in websocket:
            message = json.loads(message_json)
            await consumer(websocket, message)
    except websockets.exceptions.ConnectionClosedError as err:
        print(err)
    finally:
        await remove_websocket(websocket)


ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
here = os.path.dirname(os.path.abspath(__file__))
cert_pem = os.path.join(here, "fullchain.pem")
key_pem = os.path.join(here, "privkey.pem")
ssl_context.load_cert_chain(cert_pem, keyfile=key_pem)

app = web.Application()

cors = aiohttp_cors.setup(app, defaults={
    "https://app.joincowork.com": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
    ),
    # local enabled for debugging
    "http://local.joincowork.com": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
    )
})

resource = cors.add(app.router.add_resource("/"))
cors.add(resource.add_route("GET", hello))


start_server = websockets.serve(consumer_handler, "ws.joincowork.com", 4433, ssl=ssl_context)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_until_complete(web.run_app(app, ssl_context=ssl_context, port=443))
asyncio.get_event_loop().run_forever()
