import os
import binascii
from pathlib import Path
import json
import scrypt

import psycopg2
from database import config
from secrets import token_urlsafe
from database_connector import DatabaseConnector

class AccountsDatabaseConnector(DatabaseConnector):

    def __init__(self):
        super().__init__()
        self.connection = self.connect()

    def connect(self):
        self.connection = None
        try:
            params = config()

            # connect to the PostgreSQL server
            self.connection = psycopg2.connect(**params)
            
            return self.connection
        except (Exception, psycopg2.DatabaseError) as error:
            print(error)
            return None


    def update_last_login(self, account_id):
        cursor = self.connection.cursor()

        cursor.execute("""UPDATE account SET last_login = NOW()::timestamp WHERE id = %s""", \
            (account_id,))

        self.connection.commit()
        cursor.close()
        return True


    def get_update_notes(self, account_id):
        cursor = self.connection.cursor()
        cursor.execute("""SELECT last_login FROM account WHERE id = %s""", \
            (account_id,))

        last_login = cursor.fetchone()[0]
        update_notes = tuple()
        if last_login == None:
            cursor.execute("""SELECT slug FROM update_notes""")
            update_notes = cursor.fetchall()
        else:
            cursor.execute("""SELECT slug FROM update_notes WHERE date > %s ORDER BY date DESC""", (last_login,))
            update_notes = cursor.fetchall()

        cursor.close()
        return update_notes


    def complete_referrals(self, username):
        cursor = self.connection.cursor()
        
        cursor.execute("""UPDATE referral SET completed = %s WHERE referee_username = %s""", \
            (True, username,))

        self.connection.commit()
        cursor.close()
        return True


    def set_pro(self, account_id, pro):
        cursor = self.connection.cursor()
        
        cursor.execute("""UPDATE account SET pro = %s WHERE id = %s""", \
            (pro, account_id,))

        self.connection.commit()
        cursor.close()
        return True


    def get_pro(self, account_id):
        cursor = self.connection.cursor()
        
        cursor.execute("""SELECT pro FROM account WHERE id = %s""", \
            (account_id,))
        pro = cursor.fetchone()[0]

        self.connection.commit()
        cursor.close()
        return pro


    def save(self, username, password):
        salt = binascii.hexlify(os.urandom(64)).decode()
        hashed_password = str(binascii.hexlify(scrypt.hash(password, salt)).decode())
        cursor = self.connection.cursor()

        user_id = token_urlsafe(8)
        cursor.execute("""SELECT username FROM account WHERE id = %s""", \
        (user_id,))
        while cursor.fetchone() is not None:
            user_id = token_urlsafe(8)
            cursor.execute("""SELECT username FROM account WHERE id = %s""", \
                (user_id,))

        cursor.execute("""INSERT INTO account (id, username, display_name, wealth, salt, password) VALUES(%s, %s, %s, %s, %s, %s)""", (user_id, username, username.split('@')[0], 0, salt, hashed_password))
        self.connection.commit()
        cursor.close()


    def update_password(self, username, password):
        salt = binascii.hexlify(os.urandom(64)).decode()
        hashed_password = str(binascii.hexlify(scrypt.hash(password, salt)).decode())
        cursor = self.connection.cursor()
        
        cursor.execute("""UPDATE account SET password = %s, salt = %s WHERE username = %s""", \
            (hashed_password, salt, username,))

        self.connection.commit()
        cursor.close()
        return True


    def verify(self, username, password):
        account = self.get(username)
        hashed_password = str(binascii.hexlify(scrypt.hash(password, account[2])).decode())
        if hashed_password == account[3]:
            return True
        else:
            return False


    def get(self, username):
        print("Getting account " + username)
        exists = False
        account = []
        cursor = self.connection.cursor()
        cursor.execute("""SELECT id FROM account WHERE username = %(username)s""", {'username': username})
        userid_pair = cursor.fetchone()
        username_exists = userid_pair is not None
        if username_exists:
            userid = userid_pair[0]
            cursor.execute("""SELECT username, wealth, salt, password FROM account WHERE id = %(id)s""", {'id': userid})
            account = cursor.fetchone()
            account_exists = account is not None
            exists = username_exists and account_exists
        cursor.close()
        if exists:
            return account
        return None


    def make_token(self):
        token = binascii.hexlify(os.urandom(64)).decode()
        return token