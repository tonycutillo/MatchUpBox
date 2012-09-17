===========================================================
 beta version 1.0
===========================================================

0 - PREREQUISITES SETUP

To run MatchUpBox, please download and install
- Python 2.7
- M2Crypto
- Twisted
- zope interface
- pysqlite
- pyOpenSSL
- Python Imaging Library
- setuptools

================================================================================

1 - RUN MATCHUPBOX

- go to the website www.matchupbox.com, click on "Windows only for the moment" and take the step 1: get an invitation
  - fill the form and click on "get my invitation"
  - save your invitation file in the MatchUpBox folder
- in case your home nat does not support the UPnP protocol please:
  - map manually the following ports to your pc: 4000 UDP, 5000 TCP and 443 TCP
  - edit the ip.dat file in the conf folder as follows:
    your_public_ip 5000 4000 your_private_ip 1
- open a shell and run
  >> python MatchUpBox.py
  and enter again the same information provided while filling the form  
- once read on the shell the message "I HAVE BUILT MY MATRYOSHKA" it is possible to use the social network facilities

================================================================================

2 - RESET MATCHUPBOX

in case of problems, you can clean your MatchUpBox account by executing the Reset script.
This operation deletes permanently all your data, comprising your friendlist.