This is a little chat server/client program for our crryptography assignment.

# Usage
---
1. Git clone the repo and cd into it
2. Run `python3 client.py <chat server domain or IP>`
3. When prompted, enter the username by which you want to be known.
4. Start chatting!

# Features
---
By default, all your messages are broadcast to everyone. However, you can also use private messaging if you know the name of the user you want to message.

This is done as follows:
```bash
/msg <recipient_name> <message>
```

As a recipient, you will then get a message labeled **[PRIVATE]** if you are logged in when this happens.

If you are not logged in, you can view any private messages sent to you through:

```bash
/inbox
```

This will give you a list of private messages you have received.
