__author__ = 'wfg2af'

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
class userMessages:
    #Each user will have the public key of any other user.
    UserMap = {}
    UserName = ""
    def __init__(self, UserName = "", UserMap = {}, key = None):
        self.UserMap = UserMap
        self.UserName = UserName
        self.key = key
    #Upon user creation each user will have
    def send_message(self, message, recipient):
        if self.UserMap.get(recipient,None) is not None:
            public_key = self.UserMap.get(recipient)
            encrypted = public_key.encrypt(message.encode(), 32)[0]
            hash = SHA256.new(encrypted).digest()
            signature = self.key.sign(hash, self.UserName)
            return public_key.encrypt(message.encode(), 32)[0], signature, self.UserName
        else:
            return None

    def receive_message(self, message_tuple):
        message = message_tuple[0]
        signature = message_tuple[1]
        sender = message_tuple[2]
        hash = SHA256.new(message).digest()
        if self.UserMap.get(sender, None) is not None and self.UserMap.get(sender).verify(hash, signature):
            return self.key.decrypt(message).decode()
        else:
            return sender + " did not send this message"

if __name__ == "__main__":
    random_generator = Random.new().read
    k1 = RSA.generate(1024, random_generator)
    random_generator = Random.new().read
    k2 = RSA.generate(1024, random_generator)
    UM = {"User1": k1.publickey(), "User2": k2.publickey()}
    user_1 = userMessages(UserName = "User1", UserMap = UM, key = k1)
    user_2 = userMessages(UserName = "User2", UserMap = UM, key = k2)

    prompt = ""
    while(True):
        prompt = input("Who is sending a message?: ")
        if prompt == "-1":
            break
        elif prompt == "User1":
            prompt = input("What message do you want to send?: ")
            sent = user_1.send_message(prompt, "User2")
            #message would be stored in data base here and user 2 would be able to receive message at any time.
            print("User1 sent: " + user_2.receive_message(sent))
        elif prompt == "User2":
            prompt = input("What message do you want to send?: ")
            sent = user_2.send_message(prompt, "User1")

            print("User2 sent: " + user_1.receive_message(sent))
        else:
            print("doing invalid signature test")
            k3 = RSA.generate(1024, Random.new().read)
            print("The message being sent to user1 is: hi")
            message = k1.publickey().encrypt("hi".encode(), 32)[0]
            hash = SHA256.new(message).digest()
            signature = k3.sign(hash, 'User2')
            print(user_1.receive_message((message,signature,"User2")))
