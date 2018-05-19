#!/usr/bin/env python

import sys
import imaplib
import getpass
import email
import email.header
import datetime

import checkdmarc
import re
import json
from pygments import highlight, lexers, formatters


EMAIL_ACCOUNT = "asdf@domain.com"

# Use 'INBOX' to read inbox.  Note that whatever folder is specified, 
# after successfully running this script all emails in that folder 
# will be marked as read.
EMAIL_FOLDER = "INBOX"


def process_mailbox(M):
    """
    Do something with emails messages in the folder.  
    For the sake of this example, print some headers.
    """

    report = {
      'totalDomains': 0,
      'spf': {
        'count': 0,
        'pass': 0,
        'notPass': 0,
      },
      'dkim': {
        'count': 0,
        'fail': 0,
        'SenderAlignmentFailure': 0,
      },
      'dmarc': {
        'count': 0,
        'pass': 0,
        'fail': 0,
        'policy': {
          'reject': 0,
          'quarantine': 0,
          'none': 0,
        },
        'appliedPolicy': {
          'reject': 0,
          'quarantine': 0,
          'none': 0,
        },
      },
    }


    rv, data = M.search(None, "ALL")
    if rv != 'OK':
        print("No messages found!")
        return

    for num in data[0].split():
        report['totalDomains'] += 1
        #domainCount += 1

        rv, data = M.fetch(num, '(RFC822)')
        if rv != 'OK':
            print("ERROR getting message", num)
            return

        msg = email.message_from_bytes(data[0][1])

        mailfrom = email.header.make_header(email.header.decode_header(msg['FROM']))
        mfrom = str(mailfrom)


        cur_domain = mfrom.split("@")[1]
        cur_domain = cur_domain.replace(">", "")

        # print('Message FROM: %s: ' % (mfrom))
        # print('Message Domain: %s: ' % (str(cur_domain)))
        # print('Message DKIM: %s: ' % (dkimhdr))

        if 'Received-SPF' in msg:
          spfhdr = email.header.make_header(email.header.decode_header(msg['Received-SPF']))
          spfhdr = str(spfhdr)

          report['spf']['count'] += 1

          if 'ARC-Authentication-Results' in msg:
            arc = email.header.make_header(email.header.decode_header(msg['ARC-Authentication-Results']))
            arcAuthResults = str(arc)
            if str("spf=pass") in arcAuthResults:
              report['spf']['pass'] += 1
            else:
              report['spf']['notPass'] += 1


        if 'ARC-Authentication-Results' in msg:
          arc = email.header.make_header(email.header.decode_header(msg['ARC-Authentication-Results']))
          arcAuthResults = str(arc)
          if 'DKIM-Signature' in msg:
            dkimhdr = email.header.make_header(email.header.decode_header(msg['DKIM-Signature']))
            dkimSig = str(dkimhdr)
            if str("dkim") in arcAuthResults:
              report['dkim']['count'] += 1
              #dkimCount += 1
              if str("dkim=pass") not in arcAuthResults:
                report['dkim']['fail'] += 1
                #dkimFailCount += 1
              if str("d=" + cur_domain) not in dkimSig:
                report['dkim']['SenderAlignmentFailure'] += 1


        if 'ARC-Authentication-Results' in msg:
          arc = email.header.make_header(email.header.decode_header(msg['ARC-Authentication-Results']))
          arcAuthResults = str(arc)
          if str("dmarc") in arcAuthResults:
            report['dmarc']['count'] += 1
            if str("dmarc=pass") in arcAuthResults:
              report['dmarc']['pass'] += 1
            else:
              report['dmarc']['reject'] += 1

            if str("p=REJECT") in arcAuthResults:
              report['dmarc']['policy']['reject'] += 1
            if str("p=QUARANTINE") in arcAuthResults:
              report['dmarc']['policy']['quarantine'] += 1    
            if str("p=NONE") in arcAuthResults:
              report['dmarc']['policy']['none'] += 1    

            if str("dis=REJECT") in arcAuthResults:
              report['dmarc']['appliedPolicy']['reject'] += 1
            if str("dis=QUARANTINE") in arcAuthResults:
              report['dmarc']['appliedPolicy']['quarantine'] += 1    
            if str("dis=NONE") in arcAuthResults:
              report['dmarc']['appliedPolicy']['none'] += 1 

    #print(json.dumps(report,indent=4))
    formatted_json = json.dumps(report, indent=4)

    colorful_json = highlight(formatted_json, lexers.JsonLexer(), formatters.TerminalFormatter())
    print(colorful_json)


M = imaplib.IMAP4_SSL('imap.gmail.com')

try:
    rv, data = M.login(EMAIL_ACCOUNT, getpass.getpass())
except imaplib.IMAP4.error:
    print ("LOGIN FAILED!!! ")
    sys.exit(1)

#print(rv, data)


rv, mailboxes = M.list()
# if rv == 'OK':
#     print("Mailboxes:")
#     print(mailboxes)

rv, data = M.select(EMAIL_FOLDER)
if rv == 'OK':
    print("Processing mailbox...\n")
    process_mailbox(M)
    M.close()
else:
    print("ERROR: Unable to open mailbox ", rv)

M.logout()

myList = ["nsuok.edu", "cnn.com"]

# checkdmarc.check_domains(myList)

# s = 'My name is Conrad, and blahblah@gmail.com is my email.'
# domain = re.search("@[\w.]+", s)
# print domain.group()
