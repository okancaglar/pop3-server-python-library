import sys
import os
sys.path.append('/home/marcus-aurelius/Projects/Networking/pop3_server_library/src')
print(sys.path)
from email.message import Message
from email.parser import Parser
import socket
import ssl
import unittest
from server import pop3server
from email.message import Message
from email.policy import Policy, default 
import time
import threading


class TestPOP3Server(unittest.TestCase):

    
    class ServerDataTest(pop3server.POP3ServerListener):

        def __init__(self, mailBoxes:dict[str, list[dict]], users: dict[str, str]) -> None:
            """_summary_

            Args:
                mailBoxes (dict[str, list[dict]]): dict[username, list[dict[{email:str ; email: str, marked:str ; state: bool}]]]
                users (dict[str, str]): _description_
            """
            
            super().__init__()
            self.mailboxes = mailBoxes
            self.users = users

        
        
        
        def checkUserValid(self, userName: str) -> bool:
            
            if userName in self.users.keys():
                return True
            return False
    
        def checkPassword(self, password: str, userName: str) -> bool:
            
            if password == self.users.get(userName):
                return True
            return False
        
        def getTotalMessageSizePair(self, username: str) -> tuple[int, int]:
            
            messages = self.mailboxes.get(username)
            messageCount = 0
            totalsize = 0
            if messages is not None:
                for messageDict in messages:
                    messageCount +=1
                    message = messageDict.get("email")
                    if message is not None:
                        totalsize += len(message.encode())

            return messageCount, totalsize

        def getMailsSize(self, username: str) -> list[int]:
            
            mailsizes = []
            mails = self.mailboxes.get(username)
            
            if mails is not None:
                for maildict in mails:
                    mail = maildict.get("email")
                    if mail is not None:
                        mailsizes.append(len(mail.encode()))
            return mailsizes

        def getMail(self, username: str, mailid: int) -> Message | None:

            mails = self.mailboxes.get(username)
            if mails is not None and len(mails) > mailid and mails[mailid].get("marked") == False:
                mailMessage = Message()
                mail = mails[mailid].get("email")
                if mail is not None:
                    headers, body = mail.split("\r\n\r\n", 1)
                    headers = headers.split("\r\n")
                    
                    return Parser(policy=default).parsestr(f'{headers[0]}\r\n'
                                                           f'{headers[1]}\r\n'
                                                           f'{headers[2]}\r\n'
                                                           f'{body.strip()}\r\n')
                                                           
            
            return None
            

        def getMailbox(self, username: str) -> dict[int, str]:
            mailbox = self.mailboxes.get(username)
            if mailbox is not None:
                result = {}
                for index, mailDict in enumerate(mailbox):
                    result[index] = mailDict.get("email")
                return result
            return {}

        def markEmailAsDeleted(self, username: str, mailid: int) -> bool:
            mails = self.mailboxes.get(username)
            if mails is not None and mailid < len(mails):
                mails[mailid]["marked"] = True
                return True
            return False

        def deleteMarkedMails(self, username: str):
            mails = self.mailboxes.get(username)
            if mails is not None:
                for index, mail in enumerate(mails):
                    if mail.get("marked"):
                        mails.pop(index)

        def unmarkDeletedMessages(self, username: str) -> bool:
            
            messages = self.mailboxes.get(username)
            flag = False
            if messages is not None:
                for message in messages:
                    if message.get("marked"):
                        message["marked"] = False
                        flag = True
            return flag
    
    
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.server = None
        self.th = None

    
    def setUp(self) -> None:

        mail1 = {"marked": False, "email": "from: test1@testhost.com\r\nto: test2@testhost.com\r\nsubject: test1 email."}
        mail2 = {"marked": False, "email": "from: test3@testhost.com\r\nto: test2@testhost.com\r\nsubject: test2 email."}
        mail3 = {"marked": False, "email": "from: test4@testhost.com\r\nto: test2@testhost.com\r\nsubject: test3 email."}
        users = {"test2@testhost.com": "test2pass","test1@testhost.com": "test1pass", "test3@testhost.com": "test3pass", "test4@testhost.com": "test4pass"}
        mailList = {"test2@testhost.com": [mail1, mail2, mail3]}

        listener = TestPOP3Server.ServerDataTest(mailList, users)

        certfile = os.path.join(os.path.dirname(__file__), "certs/server.crt")
        keyfile = os.path.join(os.path.dirname(__file__), "certs/server.key")
        print(certfile)
        print(keyfile)
        self.server = pop3server.ThreadedTLSPOP3Server(("localhost", 55551), pop3server.ThreadedPOP3RequestHandler, listener, certfile=certfile, keyfile=keyfile)
        time.sleep(2)
        self.th = threading.Thread(target=self.server.serve_forever)
        self.th.daemon = True
        self.th.start()
        print(self.server.server_address)
        
    def tearDown(self) -> None:
        if self.server is not None:
            print("teardown invoked")
            self.server.closeServer()
        
        if self.th is not None:
            print(self.th.is_alive())
            print(self.th.name)
            self.th.join()
            print("after join")


        for thread in threading.enumerate():
            print(thread.name, thread.is_alive())    
        return    

    def test_auth(self):
   
        clientsocket = socket.socket(socket.AF_INET, type=socket.SocketKind.SOCK_STREAM)
        #clientsocket.connect(("localhost", 9980))
        certfile = os.path.join(os.path.dirname(__file__), "certs/server.crt")
        context = ssl.create_default_context(cafile=certfile)
        context.check_hostname = False
        with context.wrap_socket(clientsocket, server_hostname="localhost") as sslclientsocket:
            sslclientsocket.connect(("localhost", 55551))
            sslclientsocket.sendall("USER test2@testhost.com".encode())
            userresponse = sslclientsocket.recv(1024).decode().strip()
            print("end of the auth test")
            self.assertEqual(userresponse, "+OK")


if __name__ == "__main__":
    unittest.main()

