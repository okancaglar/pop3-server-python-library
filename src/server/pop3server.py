from collections.abc import Callable
from concurrent.futures import thread
from curses.ascii import isdigit
from email import message
import email
from pydoc import Helper
import socketserver
from socketserver import  BaseRequestHandler
import ssl
import threading
from typing import Any, TypeVar, Type
from socket import socket, socket as _socket
from abc import ABC, abstractmethod
import email.message as emassage
import os
import socket as sock
import time


"""
ssl.SSLEOFError: EOF occurred in violation of protocol (_ssl.c:2426):
    if socket connection is terminated and server try to send data via closed socket python raise this exception.


"""


"""
    todo you must implement listener pattern to server also make this module library than a app.
    todo take care threading side.
"""

"""
POP3 COMMANDS

USER

    Purpose: Used to pass the user's identifier to the server.
    Format: USER <username>
    Response: Positive (+OK) if the username is accepted; otherwise, negative (-ERR).

PASS

    Purpose: Used to pass the user's password to the server following the USER command.
    Format: PASS <password>
    Response: Positive (+OK) if the login is successful; otherwise, negative (-ERR).

STAT

    Purpose: Requests the mailbox status, specifically the number of messages and the total size.
    Format: STAT
    Response: Positive (+OK), followed by the number of messages and the total size in bytes.

LIST

    Purpose: Lists the messages and their sizes. Without an argument, it lists all messages; with an argument, it lists the specified message.
    Format: LIST or LIST <message number>
    Response: For all messages, a list of messages with their numbers and sizes; for a single message, the size of the message.

RETR

    Purpose: Retrieves a specific message from the server.
    Format: RETR <message number>
    Response: The full message including headers and body.

DELE

    Purpose: Marks a message for deletion from the mailbox. Messages are actually deleted when the QUIT command is sent.
    Format: DELE <message number>
    Response: Positive (+OK) if successful; otherwise, negative (-ERR).

NOOP

    Purpose: No operation. Used to keep the connection alive or check the status of the connection.
    Format: NOOP
    Response: Positive (+OK).

RSET

    Purpose: Resets the session state, unmarking any messages marked for deletion.
    Format: RSET
    Response: Positive (+OK).

TOP

    Purpose: Retrieves the headers of a message, and optionally, a specified number of lines from the body.
    Format: TOP <message number> <line count>
    Response: The headers of the message and the requested number of lines from the body.

UIDL

    Purpose: Lists the unique identifiers for the messages. Can be used with or without a message number argument.
    Format: UIDL or UIDL <message number>
    Response: For all messages, a list of unique identifiers; for a single message, the unique identifier for that message.

QUIT

    Purpose: Ends the session, commits any pending changes (such as message deletions), and closes the connection.
    Format: QUIT
    Response: Positive (+OK), indicating the server is closing the connection.
"""



class POP3ServerListener(ABC):

    """ You have to implement this methods:

    def checkUserValid ||
    def checkPassword ||
    def getTotalMessageSizePair ||
    def getMailbox ||
    def getMailsSize ||
    def getMail ||
    def markEmailAsDeleted ||
    def unmarkDeletedMessages ||
    def deleteMarkedMails

    """

    @abstractmethod
    def checkUserValid(self, userName:str) -> bool:
        """ Check user name exist.

        Args:
            userName (str): user name

        Returns:
            bool: if user name valid returns true
        """
        

    @abstractmethod
    def checkPassword(self, password:str, userName:str) -> bool:
        """ Password Checker

        Args:
            password (str): password
            userName (str): user name

        Returns:
            bool: if successful returns true
        """
    

    @abstractmethod
    def getTotalMessageSizePair(self, username:str)-> tuple[int, int]:
        """ getter for Total number of messages and total size of messages

        Args:
            username (str): user name

        Returns:
            tuple[int, int]: tuple[total number of messages, total size of messages]
        """
        
    
    @abstractmethod
    def getMailbox(self, username:str)-> dict[int, str]:
        """ gets user's mailbox

        Args:
            username (str): user name

        Returns:
            dict[int, str]: dict{mail_id, mail}
        """
    @abstractmethod
    def getMailsSize(self, username:str) -> list[int]:
        """ gets mails' sizes

        Args:
            username (str): user name

        Returns:
            list[int]: list[size of the mails]
        """

    @abstractmethod
    def getMail(self, username:str, mailid:int) -> emassage.Message | None:
        """ gets email messages according to specific id

        Args:
            username (str): username
            mailid (int): mail id

        Returns:
            emassage.EmailMessage: parsed mail object
        """

    @abstractmethod
    def markEmailAsDeleted(self, username:str, mailid:int) -> bool:
        """ marks email as deleted

        Args:
            username (str): user name
            mailid (int): id of the mail_

        Returns:
            bool: operation is successfull or not
        """

    @abstractmethod
    def unmarkDeletedMessages(self, username:str) -> bool:
        """ unmarks messages as deleted

        Args:
            username (str): user name

        Returns:
            bool: operation successfull or not
        """
        
    @abstractmethod
    def deleteMarkedMails(self, username:str):
        """ deletes the marked mails

        Args:
            username (str): user name

        """

# class POP3ServerData():

#     def __init__(self, mailboxes: dict[str,list[list]], users: dict[str,str], userStatus:dict[str,bool]) -> None:
#         """_summary_

#         Args:
#             mailboxes (dict[str:list[list]]): dict[userName:list[list[deleted, message]]]
#             users (dict[str:str]): [userName:password]
#             userStatus (dict[str:bool]): [userName:connected]        
#             """
        
#         self.mailboxes = mailboxes
#         self.users = users
#         self.userStatus = userStatus

#     def checkUserValid(self, userName:str) -> bool:
#         """ Checks user exist or not

#         Args:
#             userName (str): mail name of the user

#         Returns:
#             bool: if the user account exist return true otherwise false
#         """

#         if self.users.get(userName):
#             return True
#         return False
        

#     def checkUserPassword(self, userName: str, password:str) -> bool:
#         """checks the user password true or not

#         Args:
#             userName (str): account name
#             password (str): account password

#         Returns:
#             bool: password true or not
#         """

#         if self.users.get(userName) and self.users.get(userName) == password:
#             return True
#         return False 
    
#     def getTotalMessagesAndSize(self, userName: str) -> tuple[int, int]:
#         """getter for total message number and total size of user's mailbox

#         Args:
#             userName (str): user name of the account

#         Returns:
#             tuple[int, int]: (total number of messages, total size of the messages in bytes)
#         """

#         totalMessage = 0
#         totalSize = 0

#         messages = self.mailboxes.get(userName)
#         if messages is not None:
#             for messageTuple in messages:
#                 if messageTuple[0] == False:    
#                     totalMessage += 1
#                     totalSize += len(messageTuple[1].encode("ascii"))
            
#         return (totalMessage, totalSize)
    
#     def getMessageList(self, userName:str) -> list[str]:

#         messageList = []
#         messages = self.mailboxes.get(userName)
#         if messages is not None:
#             for messageTuple in messages:
#                 if messageTuple[0] == False:    
#                     messageList.append(messageTuple[1])

#         return messageList
        
#     def markEmailAsDeleted(self, userName:str, messageNo:int) -> bool:
#         """_summary_

#         Args:
#             userName (str): _description_
#             messageNo (int): _description_

#         Returns:
#             bool: if operation is successful return true, if not false
#         """
        
#         try:
#             mails = self.mailboxes.get(userName)
#             if mails is not None:
#                 mails[messageNo][0] = True
#                 return True
#         except Exception:
#             pass
        
#         return False

#     def unmarkDeletedMessages(self, userName:str) -> tuple[int, int]:
#         """_summary_

#         Args:
#             userName (str): _description_

#         Returns:
#             int: _description_
#         """

#         mailNumber = 0
#         mailSize=0
#         mails = self.mailboxes.get(userName)
#         if mails is not None:
#             for mail in mails:
#                 mail[0] = False
#                 mailNumber += 1
#                 mailSize += len(mail[1].encode())
        
#         return mailNumber, mailSize

#     def getMessage(self, userName:str, index:int) -> str | None:
#         """_summary_

#         Args:
#             userName (str): _description_
#             index (int): _description_

#         Returns:
#             str | None: _description_
#         """


#         try:
#             messageList = self.mailboxes.get(userName)
#             if messageList is not None and messageList[index][0] == False:
#                 return messageList[index][1]
#             else:
#                 return None
#         except Exception:
#             return None
                
#     def deleteMarkedMails(self, userName: str) -> None:
#         """_summary_

#         Args:
#             userName (str): _description_
#         """
    
#         messageList = self.mailboxes.get(userName)
#         if messageList is not None:
#             for index, message in enumerate(messageList):
#                 if message[0] == True:
#                     messageList.pop(index)
                




#     #todo mailbox operation implementation
#     #todo make synch the data operations

class ThreadedPOP3RequestHandler(socketserver.StreamRequestHandler):
    
    
    
    def __init__(self, request, client_address, server: socketserver.TCPServer) -> None:
        super().__init__(request, client_address, server)
        self.listener = None
        self.userName = ""
        self.userPassword = ""
    
    class ProtocolStatus():
        AUTH = "AUTHORIZATION"
        TRNSCTN = "TRANSECTION"
        UPDATE = "UPDATE"
    
    def handle(self) -> None:
        self.listener = self.server.listener
        status = self.ProtocolStatus.AUTH
        while True:

          command, *args = self.request.recv(1024).decode("ascii").strip().split(" ")
          if command != "":  
            if status == self.ProtocolStatus.AUTH:

                if command.upper() == "USER" and len(args) == 1:
                    if self.checkUserNameFormatValid(args[0]) and self.listener.checkUserValid(args[0]):
                        self.userName = args[0]
                        self.wfile.write("+OK\r\n".encode())
                        self.wfile.flush()

                    else:
                        self.wfile.write("-ERR invalid user name\r\n".encode())
                        self.wfile.flush()
                        break
                    
                elif command.upper() == "PASS" and len(args) == 1:
                    if self.checkUserPasswordFormat(args[0]) and self.listener.checkPassword(args[0], self.userName):
                        self.password = args[0]
                        self.wfile.write("+OK authentication is correct\r\n".encode())
                        self.wfile.flush()
                        status = self.ProtocolStatus.TRNSCTN
                    else:
                        self.wfile.write("-ERR authentication is failed\r\n".encode())
                        self.wfile.flush()
                        break
                else:
                   self.wfile.write("-ERR invalid command or args\r\n".encode())
                   self.wfile.flush()

            elif status == self.ProtocolStatus.TRNSCTN:

                if command.upper() == "STAT" and len(args) == 0:
                    
                    totalMessage, totalSize = self.listener.getTotalMessageSizePair(self.userName)
                    self.wfile.write(f"+OK {str(totalMessage)} {str(totalSize)}\r\n".encode())
                    self.wfile.flush()
                    
                elif command.upper() == "LIST":

                    totalMessage, totalSize = self.listener.getTotalMessageSizePair(self.userName)
                    mailbox = self.listener.getMailsSize(self.userName)

                    if len(args) == 0:

                        self.wfile.write(f"+OK {str(totalMessage)} {str(totalSize)}\r\n".encode())

                        for index, messageSize in enumerate(mailbox):
                            self.wfile.write(f"+OK {str(index)} {str(messageSize)}\r\n".encode())
                        
                        # multiline responses ends with '.' 
                        self.wfile.write(".\r\n".encode())
                        self.wfile.flush()

                    elif len(args) == 1 and self.listCommand_isValidArg(args[1], len(mailbox)):

                        self.wfile.write(f"+OK {args[1]} {str(mailbox[args[0]])}\r\n".encode())
                        self.wfile.flush()
                    
                    else: 
                        self.wfile.write("-ERR invalid argumant\r\n".encode())
                        self.wfile.flush()


                    
                elif command.upper() == "RETR":
                    if len(args) == 1 and args[0].isdigit():
                        message = self.listener.getMail(self.userName, int(args[0]))
                        #only string body is supported
                        if message is not None and not message.is_multipart():
                            mailSize = len(message.as_string().encode())
                            self.wfile.write(f"+OK {mailSize} octets\r\n{message.as_string().strip()}\r\n.\r\n".encode())
                            self.wfile.flush()
                        else:
                            self.wfile.write("-ERR invalid argumant\r\n".encode())
                            self.wfile.flush()
                    else:
                        self.wfile.write("-ERR invalid argumant\r\n".encode())
                        self.wfile.flush()

                elif command.upper() == "DELE":
                    if len(args) == 1 and args[0].isdigit():
                        if self.listener.markEmailAsDeleted(self.userName, int(args[0])):
                            self.wfile.write(f"+OK message {args[0]} is deleted\r\n".encode())
                            self.wfile.flush()
                        else:
                            self.wfile.write("-ERR invalid argumant\r\n".encode())
                        self.wfile.flush()    
                                                    
                    else:
                        self.wfile.write("-ERR invalid argumant\r\n".encode())
                        self.wfile.flush()

                elif command.upper() == "NOOP":
                    self.wfile.write("+OK\r\n".encode())
                
                elif command.upper() == "RSET":
                    
                    self.listener.unmarkDeletedMessages(self.userName)
                    mailSize = self.listener.getMailsSize(self.userName)
                    self.wfile.write(f"+OK maildrop has {str(len(mailSize))} messages ({str(sum(mailSize))})\r\n".encode())
                    self.wfile.flush()
                    
                elif command.upper() == "UIDL":
                    #todo uidl command
                    pass
                elif command.upper() == "TOP":
                    if len(args) == 2 and args[0].isdigit() and args[1].isdigit():
                        message = self.listener.getMail(self.userName, args[0])
                        if message is None:
                            self.wfile.write("-ERR invalid argument\r\n".encode())
                            self.wfile.flush()
                        else:
                            body= self.getBody(args[1], message)
                            header = "\r\n".join(message.values())
                        
                            self.wfile.write(f"+OK\r\n{header}\r\n{body}\r\n.\r\n".encode())
                            self.wfile.flush()
                            
                elif command.upper() == "QUIT":
                    
                    if len(args) == 0:
                        self.wfile.write("+OK\r\n".encode())
                        self.wfile.flush()
                        status = self.ProtocolStatus.UPDATE
                    else:
                        self.wfile.write("-ERR invalid argument\r\n".encode())
                        self.wfile.flush()

                else:
                    self.wfile.write("-ERR\r\n".encode())
                    self.wfile.flush()

            elif status == self.ProtocolStatus.UPDATE:
                self.listener.deleteMarkedMails(self.userName)
                return
            
            else:
              self.wfile.write("-ERR invalid command or args\r\n".encode())
              self.wfile.flush()
          else:
              break
            
    def listCommand_isValidArg(self, arg, lenMessage):

        try:
            if isdigit(arg) and int(arg) < lenMessage:
                return True
        except Exception as e:
            return False
        return False
    

    def checkUserNameFormatValid(self, userName:str) -> bool:
        
        localpart, hostpart = userName.split("@", 1)
        if len(localpart) < 33 and len(localpart) > 3 and " " not in localpart and len(hostpart) < 255 and len(hostpart) > 5 and " " not in hostpart:
            return True
        return False
    
    def checkUserPasswordFormat(self, password):

        if len(password) < 32 and len(password) > 8 and " " not in password:
            return True
        return False
    
    def getBody(self, numberOfLine:int, message: emassage.Message) -> str:

        return ""

class ThreadedPOP3Server(socketserver.ThreadingMixIn, socketserver.TCPServer):

    def __init__(self,server_address: Any, requestHandlerClass, listener: POP3ServerListener, bind_and_activate: bool = True) -> None:
        
        """
        maildrops structure:
            str: user mail name
            list: user's mailbox

        activeSessions:
            list: currently active user sessions based on that user cannot be estabhlished more than one session
        
        """
        super().__init__(server_address, requestHandlerClass, bind_and_activate)         
        self.activeSessions = []
        self.listener = listener
        self.socket.listen(10000)
    """   
    def server_bind(self) -> None:
        self.socket.bind(self.server_address)
        self.daemon_threads = True
        print(self.socket_type)
        print(self.daemon_threads)
        print(self.socket)    
    """
    def get_request(self):
        request, address =  self.socket.accept()     
        return request, address
    
class ThreadedTLSPOP3Server(ThreadedPOP3Server):

    def __init__(self, server_address: Any, RequestHandlerClass, listener: POP3ServerListener, bind_and_activate: bool = True, 
                 certfile:str = "", keyfile:str = "") -> None:
        super().__init__(server_address, RequestHandlerClass, listener, bind_and_activate)
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if certfile != "" and keyfile != "":
            self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        elif certfile != "":
            self.context.load_cert_chain(certfile=certfile) 
        self.socket = self.context.wrap_socket(self.socket, server_side=True)

    def startServer(self) -> None:

        with self:
            serverthread = threading.Thread(target=self.serve_forever)
            serverthread.daemon = True
            serverthread.start()
            print("server start running...")
            #if you dont put join method to the thread that serving runnning on will exite when this method has complited.
            #to prevent it use join method which make the thread that server.startserver method running on wait until the thread is terminated
            serverthread.join()
            

    def closeServer(self):
        if self is not None:
            self.shutdown()
            #threading.Thread(target=self.server_close).start()
            print("end of closeserver")


    



