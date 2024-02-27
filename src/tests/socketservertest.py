import socketserver
import threading
import socket
class Handler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, server: socketserver.BaseServer) -> None:
        super().__init__(request, client_address, server)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate: bool = True) -> None:
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)


class ThreadedTLSTCPServer(ThreadedTCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate: bool = True) -> None:
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)


def main():

    server = ThreadedTLSTCPServer(("localhost", 9999), RequestHandlerClass=Handler)
    serverThread = threading.Thread(target=server.serve_forever)
    serverThread.daemon = True
    serverThread.start()


def sockettest():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 9999))
    s.listen()
    s.accept()
    print("Listening on port 9999")

if __name__ == "__main__":
    main()
