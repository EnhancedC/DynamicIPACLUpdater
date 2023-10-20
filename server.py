import mysql.connector
from mysql.connector import Error
import mysql.connector.errors as mysqlerrors
import pandas as pd
import logging
import os
import platform
import sys
import yaml
import traceback

rootLogger=logging.getLogger(os.path.splitext(os.path.basename(__file__))[0])
import socket
import dns.resolver
import argparse

import time

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization



class server:
    def __init__(self,DB_INFO : tuple):
        self.DB_NAME=DB_INFO['DB_NAME']
        self.DB_HOST=DB_INFO['DB_LOCATION']
        self.DB_USER=DB_INFO['DB_USER_NAME']
        self.DB_PASS=DB_INFO['DB_PASSWORD']
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dnsAddress=dns.resolver.Resolver().nameservers
        s.connect((str(dnsAddress[0] if isinstance(dnsAddress,list) else dnsAddress), 80))
        self.IPV4=s.getsockname()[0]
        s.close()
        self.ACTIVEDBCONNECTION=self.create_db_connection()
    def create_db_connection(self):
        connection = None
        while connection==None:
            try:
                rootLogger.info(f"Connecting to DB:{self.DB_NAME} with user '{self.DB_USER}'@'{self.IPV4}'")
                connection = mysql.connector.connect(host=self.DB_HOST,user=self.DB_USER,passwd=self.DB_PASS,database=self.DB_NAME)
                rootLogger.info("MySQL Database connection successful")
                return connection
            except mysqlerrors.ProgrammingError:
                rootLogger.critical(f"Error Could not Connect to: '{self.DB_HOST} with User: '{self.DB_USER}''")
                rootLogger.debug(traceback.format_exc())
                sys.exit()
            except mysqlerrors.DatabaseError:
                rootLogger.error(f'Connection Could not be Established to: "{self.DB_HOST}"')
                rootLogger.debug(traceback.format_exc())
            except Exception:
                rootLogger.critical(f"Error Could not Connect to: '{self.DB_HOST} with User: '{self.DB_USER}''")
                rootLogger.debug(traceback.format_exc())
                sys.exit()
    def checkDBConnection(self)-> bool:
        if self.ACTIVEDBCONNECTION.is_connected():
            return True
        else:
            rootLogger.info(f"Connection To Database lost")
            while True:
                try:
                    rootLogger.info(f"Attempting to Reconnect...")
                    self.ACTIVEDBCONNECTION.reconnect(attempts=2,delay=5)
                    if self.ACTIVEDBCONNECTION.is_connected():
                        return True
                    else:
                        rootLogger.info(f"Connection Failed")
                except:
                    rootLogger.debug(traceback.format_exc())
            
    def showTable(self) -> dict:
        pass

    def getTableLength(self,table) -> int:
        if self.checkDBConnection():
            cursor=self.ACTIVEDBCONNECTION.cursor()
            try:
                cursor.execute(f'SELECT COUNT(*) FROM {table}')
                count=cursor.fetchone()[0]
            except:
                rootLogger.debug(traceback.format_exc())
                count=None
            cursor.close()
            return count

    def getTableFromQuery(self,table,query) -> list:
        if self.checkDBConnection():
            cursor=self.ACTIVEDBCONNECTION.cursor()
            try:
                cursor.execute(f"SELECT * FROM {table} WHERE USER = '{query}'")
                count=cursor.fetchall()
            except:
                rootLogger.debug(traceback.format_exc())
                raise SystemExit
            return count
        
    def insert(self,table : str, data: dict):
        pass

    def addToPubkeyDB(self,table : str, data: dict):
        if self.checkDBConnection():
            cursor=self.ACTIVEDBCONNECTION.cursor()
            if 'id' in data:
                cursor.execute(f'INSERT INTO {table} VALUES ("{data["id"]}","{data["user"]}","{data["pubkey"]}")')
            else:
                cursor.execute(f"INSERT INTO {table} (user,pubkey,hasPrivateKey) VALUES (%s,%s,%s)",(data['user'], data['pubkey'],data['usePrvKey']))
            self.ACTIVEDBCONNECTION.commit()
            affectedId=cursor.lastrowid
            cursor.close()
            return affectedId
    @staticmethod
    def generatePrivatePublicKey() -> tuple:
        private_key = ed25519.Ed25519PrivateKey.generate()
        return (private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption()).decode(encoding='utf-8'),private_key.public_key().public_bytes_raw())
    
    def getCountFromTable(self,table,query,value) -> int:
        if self.checkDBConnection():
            cursor=self.ACTIVEDBCONNECTION.cursor()
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE {query}='{value}'")
                count=cursor.fetchone()
            except:
                rootLogger.debug(traceback.format_exc())
                raise SystemExit
            return count[0]
    def createNewConf(self,user: str,usePrivateKeyEncryption: bool):
        privateKey, publicKey= self.generatePrivatePublicKey()
        rowID=self.addToPubkeyDB('public_keys',{'user':user,'pubkey':publicKey,'usePrvKey':usePrivateKeyEncryption})
        if usePrivateKeyEncryption:
            pass
        with open(f'{user}.py','x') as newfile:
            newfile.write(self.generateClientFile(privateKey,user,rowID))

    @staticmethod
    def generateClientFile(privateKey,user: str,id: int)-> str:
        base=f'''
import os
PUBLIC_KEY="""{privateKey}"""
USER_NAME='{user}'
KEY_ID=int({id})
if True:
    print(PUBLIC_KEY)
'''
        return base

if __name__ == "__main__":
    rootLogger.setLevel(logging.DEBUG)
    loggingClientHandler=logging.FileHandler(os.path.join(os.path.splitext(f'/var/log/{os.path.basename(__file__)}')[0]+'.log')) if platform.system() == 'Linux' else logging.FileHandler(os.path.join(os.path.realpath(sys.path[0]),f'{os.path.splitext(os.path.basename(__file__))[0]}'+'.log'))
    loggingFileHandler=logging.StreamHandler()
    loggingClientHandler.setLevel(logging.DEBUG)
    loggingFileHandler.setLevel(logging.DEBUG)
    loggingClientHandler.setFormatter(logging.Formatter('%(asctime)s: %(levelname)s: %(funcName)s: %(message)s'))
    loggingFileHandler.setFormatter(logging.Formatter('%(asctime)s: %(levelname)s: %(funcName)s: %(message)s'))
    rootLogger.addHandler(loggingFileHandler)
    rootLogger.addHandler(loggingClientHandler)
    argPrs=argparse.ArgumentParser()
    argPrs.add_argument('sdf',choices=['server','create_config'],default='server',nargs='?')
    afwe=argPrs.parse_args()
    print(afwe)
    with open('conf.yaml','r') as yml:
        settings=yaml.safe_load(yml)
    test=server(settings['DB_INFO'])
    test.createNewConf('archie',False)