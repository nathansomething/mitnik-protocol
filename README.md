In order to run the program, first go to src directory

To start server:
~~~~
python server.py
~~~~

To start client:
~~~~
python client.py
~~~~

The user's credentials that can be used to login are stored in users.json. Right now there are 3 users that can be used to login
~~~~
nam: 1234
nathan: 1234
luu: 1234
~~~~

To send message from one user to another:
~~~~
send [username] [message]
~~~~

To list all users online:
~~~~
list
~~~~
where username is the username of the sender and message is the message we want to send. The list of users that can be used to login is stored in users.json
