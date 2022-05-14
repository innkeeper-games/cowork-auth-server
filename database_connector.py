from abc import ABC, abstractmethod

import psycopg2
from database import config
from secrets import token_urlsafe

class DatabaseConnector(ABC):

    def connect(self):
        connection = None
        try:
            params = config()

            # connect to the PostgreSQL server
            connection = psycopg2.connect(**params)
            
            return connection
        except (Exception, psycopg2.DatabaseError) as error:
            print(error)
            return None

    
    def get_id_for_username(self, username):
        exists = False
        account = []
        connection = self.connect()
        cursor = connection.cursor()
        cursor.execute("""SELECT id FROM account WHERE username = %(username)s""", {'username': username})
        userid_pair = cursor.fetchone()
        username_exists = userid_pair is not None
        if username_exists:
            userid = userid_pair[0]
            return userid
        return None


    def get_username_for_id(self, id):
        exists = False
        account = []
        connection = self.connect()
        cursor = connection.cursor()
        cursor.execute("""SELECT username FROM account WHERE id = %s""", (id,))
        userid_pair = cursor.fetchone()
        username_exists = userid_pair is not None
        if username_exists:
            userid = userid_pair[0]
            return userid
        return None
    

    def get_display_name_for_id(self, id):
        exists = False
        account = []
        connection = self.connect()
        cursor = connection.cursor()
        cursor.execute("""SELECT display_name FROM account WHERE id = %s""", (id,))
        userid_pair = cursor.fetchone()
        display_name_exists = userid_pair is not None
        if display_name_exists:
            userid = userid_pair[0]
            return userid
        return None


    def get_wealth_for_id(self, id):
        exists = False
        account = []
        connection = self.connect()
        cursor = connection.cursor()
        cursor.execute("""SELECT wealth FROM account WHERE id = %s""", (id,))
        userid_pair = cursor.fetchone()
        display_name_exists = userid_pair is not None
        if display_name_exists:
            weath = userid_pair[0]
            return weath
        return None