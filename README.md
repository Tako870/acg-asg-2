This is a little chat server/client program for our cryptography assignment.

# Usage
---
1. Git clone the repo and cd into it
2. Run `python3 client.py <chat server domain or IP>` (note: our server is at `52.221.50.162`)
3. When prompted, enter the username by which you want to be known.
4. Start chatting!

# Features
---
By default, all your messages are broadcast to everyone. Just type and press enter.

```bash
Hello all!
```

However, you can also use private messaging if you know the name of the user you want to message.

This is done as follows:
```bash
/secure <recipient_name> <message>
```

As a recipient, you will then get a message labeled **[PRIVATE]** if you are logged in when this happens.

This will give you a list of private messages you have received.

To quit:
```bash
/quit
```