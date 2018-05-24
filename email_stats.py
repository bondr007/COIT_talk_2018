#!/usr/bin/env python

import sys
import imaplib
import getpass
import email
import email.header
import datetime

import re
import json


EMAIL_ACCOUNT = "dmarc@nsuok.edu"

# Use 'INBOX' to read inbox.  Note that whatever folder is specified, 
# after successfully running this script all emails in that folder 
# will be marked as read.
EMAIL_FOLDER = "INBOX"

def percentage(part, whole):
  return 100 * float(part)/float(whole)


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
        'pass': 0,
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
              if str("dkim=pass") in arcAuthResults:
                report['dkim']['pass'] += 1
              if str("dkim=pass") not in arcAuthResults:
                report['dkim']['fail'] += 1
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
              report['dmarc']['fail'] += 1

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

    print('Total Domains:       %s ' % (report['totalDomains']))
    print('Total Using SPF:     %s   %.2f%% of totalDomains are using SPF' % (report['spf']['count'],percentage(report['spf']['count'],report['totalDomains']) ))
    print('Total SPF PASS:      %s   %.2f%%' % (report['spf']['pass'],percentage(report['spf']['pass'],report['totalDomains']) ))
    print('Total SPF not PASS:  %s   %.2f%%' % (report['spf']['notPass'],percentage(report['spf']['notPass'],report['totalDomains']) ))
    print("")
    print('Total Using DKIM:    %s   %.2f%% of totalDomains are using DKIM' % (report['dkim']['count'],percentage(report['dkim']['count'],report['totalDomains']) ))
    print('Total DKIM FAIL:     %s   %.2f%%' % (report['dkim']['fail'],percentage(report['dkim']['fail'],report['dkim']['count']) ))
    print('Alignment Fail?:     %s   %.2f%%' % (report['dkim']['SenderAlignmentFailure'],percentage(report['dkim']['SenderAlignmentFailure'],report['dkim']['count']) ))
    print("")
    print('Total Using DMARC:   %s   %.2f%% of totalDomains are using DMARC' % (report['dmarc']['count'],percentage(report['dmarc']['count'],report['totalDomains']) ))
    print('Total DMARC FAIL:    %s   %.2f%%' % (report['dmarc']['fail'],percentage(report['dmarc']['fail'],report['dmarc']['count']) ))
    print('Total DMARC PASS:    %s   %.2f%%' % (report['dmarc']['pass'],percentage(report['dmarc']['pass'],report['dmarc']['count']) ))
    print("")
    print('DMARC Policy None:               %s   %.2f%%' % (report['dmarc']['policy']['none'],percentage(report['dmarc']['policy']['none'],report['dmarc']['count']) ))
    print('DMARC Policy Quarantine:         %s   %.2f%%' % (report['dmarc']['policy']['quarantine'],percentage(report['dmarc']['policy']['quarantine'],report['dmarc']['count']) ))
    print('DMARC Policy Reject:             %s   %.2f%%' % (report['dmarc']['policy']['reject'],percentage(report['dmarc']['policy']['reject'],report['dmarc']['count']) ))
    
    print("")
    print('DMARC Result None:               %s   %.2f%%' % (report['dmarc']['appliedPolicy']['none'],percentage(report['dmarc']['appliedPolicy']['none'],report['dmarc']['count']) ))
    print('DMARC Result Quarantine:         %s   %.2f%%' % (report['dmarc']['appliedPolicy']['quarantine'],percentage(report['dmarc']['appliedPolicy']['quarantine'],report['dmarc']['count']) ))
    print('DMARC Result Reject:             %s   %.2f%%' % (report['dmarc']['appliedPolicy']['reject'],percentage(report['dmarc']['appliedPolicy']['reject'],report['dmarc']['count']) ))
    

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
