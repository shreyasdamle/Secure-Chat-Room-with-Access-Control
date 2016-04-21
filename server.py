# -*- encoding: utf-8 -*-
#Reference: https://github.com/lunemec/python-chat
import os
import select
import socket
import sys
import signal
from time import sleep
import datetime

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256

from communication import send, receive


class ChatServer(object):

    def __init__(self, address='127.0.0.1', port=8080):
        self.clients = 0

        # Client map
        self.clientmap = {}

        # Output socket list
        self.outputsock = []

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((address, int(port)))

        print 'Generating RSA keys ....'
        self.server_privkey = RSA.generate(4096, os.urandom)
        self.server_pubkey = self.server_privkey.publickey()
        self.sign = self.server_privkey


        print 'Chat Room Server started at port', port, '...'
        self.server.listen(10)

        # Trap keyboard interrupts
        signal.signal(signal.SIGINT, self.signalhandler)

    def signalhandler(self, signal, frame):
        # Close the server
        print 'Shutting down server...'

        # Close existing client sockets
        for o in self.outputsock:
            o.close()

        self.server.close()

    def getname(self, client):
        # Return the printable name of the
        # client, given its socket...
        info = self.clientmap[client]
        host, name = info[0][0], info[1]
        return '@'.join((name, host))

    def get_just_name(self, client):
        return self.clientmap[client][1]

    def send_encrypted(self, to_who, message, name):
        try:
            encryptor = self.clientmap[to_who][2]
            msg = encryptor.encrypt(message, 0)
            msg = msg[0]
            
            message_hash = SHA256.new()
            message_hash.update(msg)
            signkey = self.sign
            #Append Signature
            signer = PKCS1_PSS.new(signkey)
            signature = signer.sign(message_hash)
            msg = '%s#^[[%s' % (msg, signature)
            #print msg
            send(to_who, msg)

        except IOError:
            send(to_who, 'PLAIN: cannot find public key for: %s' % name)

    def verify_signature(self, client, message, signature):
        try:
            
            key = self.clientmap[client][2]
            msg_hash = SHA256.new()
            msg_hash.update(message)

            verifier = PKCS1_PSS.new(key)
            return verifier.verify(msg_hash, signature)

        except IOError:
            return False

    def serve(self):
        inputs = [self.server, sys.stdin]
        self.outputsock = []

        running = 1

        while running:
            try:
                inputready, outputready, exceptready = select.select(inputs, self.outputsock, [])

            except select.error:
                break

            except socket.error:
                break

            for s in inputready:
                if s == self.server:
                    # handle the server socket
                    client, address = self.server.accept()
                    print 'Chat Server: got connection %d from %s' % (client.fileno(), address)
                    # Get client public key and send our public key
                    pubkey = RSA.importKey(receive(client))
                    send(client, self.server_pubkey.exportKey())

                    # Read the login name
                    cname = receive(client).split('NAME: ')[1]

                    # Compute client name and send back
                    self.clients += 1
                    send(client, 'CLIENT: ' + str(address[0]))
                    inputs.append(client)

                    self.clientmap[client] = (address, cname, pubkey)

                    # Send joining information to other clients
                    msg = '\n(New client (%d) entered the chat room : %s)' % (self.clients, self.getname(client))

                    for o in self.outputsock:
                        try:
                            self.send_encrypted(o, msg, self.get_just_name(o))

                        except socket.error:
                            self.outputsock.remove(o)
                            inputs.remove(o)

                    self.outputsock.append(client)

                elif s == sys.stdin:
                    # handle standard input
                    sys.stdin.readline()
                    running = 0
                else:

                    # handle all other sockets
                    try:
                        data = receive(s)

                        if data:
                            dataparts = data.split('#^[[')
                            signature = dataparts[1]
                            data = dataparts[0]
                            

                            verified = self.verify_signature(s, data, signature)
                            data = self.server_privkey.decrypt(data)
                            word = "Check online users"
                            user_list = ["Online Users:"]
                            if word in data:
                                #for item in inputs:
                                for o in self.outputsock:
                                    ur = self.get_just_name(o)
                                    user_list.append(ur)
                                
                                user_list = str(user_list)
                                print user_list
                                
                                for o in self.outputsock:
                                    #self.send_encrypted(o, msg, self.get_just_name(o))
                                    self.send_encrypted(o, user_list, self.get_just_name(o))
                        

                            if data != '\x00':
                                if verified:
                                    data = '%s [Client Signature Verified:OK]' % data

                                else:
                                    data = '%s [Not verified]' % data

                                # Send as new client's message...
                                msg = '\n# [' + self.getname(s) + ']>> ' + data

                                # Send data to all except ourselves

                                for o in self.outputsock:
                                    if o != s:
                                        self.send_encrypted(o, msg, self.get_just_name(s))
                                        

                        else:

                            print 'Chatserver: Client %d disconnected' % s.fileno()
                            self.clients -= 1
                            s.close()
                            inputs.remove(s)
                            self.outputsock.remove(s)

                            # Send client leaving information to others
                            msg = '\n(Left the Chat Room: Client from %s)' % self.getname(s)

                            for o in self.outputsock:
                                self.send_encrypted(o, msg, self.get_just_name(o))

                    except socket.error:
                        # Remove
                        inputs.remove(s)
                        self.outputsock.remove(s)

            sleep(0.1)

        self.server.close()

if __name__ == "__main__":

    if len(sys.argv) < 3:
        sys.exit('Usage: %s listen_ip listen_port' % sys.argv[0])

    ChatServer(sys.argv[1], sys.argv[2]).serve()
