#!/usr/bin/env python
#
# Copyright (c) 2021  Chad Aiena <caiena78@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# This script parses syslog sent by the Cisco ASA looking for vpn and webvpn 
# logon failures and email's them
#
# ASA_Logon_failures.py -f '<path to log file>' -emailfrom 'caiena78@gmail.com' -emailto 'email1@somedomain.com,email2@somedomain.com' 





import re
import argparse
import copy
import smtplib
import mimetypes
from email.mime.multipart import MIMEMultipart
from email import encoders
from email.message import Message
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.text import MIMEText
import os

filename="failures.csv"
csvfile=os.path.join(os.getcwd(),filename)


def checkforFiledLogin(data):
    failure={"date":"","device_ip":"","radius_ip":"","user":"","user_ip":"","match":False}
    repattern=r'([a-zA-Z]{1,4} {1,3}\d{1,2} {1,3}\d{1,2}:\d{2}:\d{2}) {1,3}(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b).+\d{1,3}-\d{1,8}: {1,3}AAA user authentication Rejected : reason = AAA failure : server = (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b) : user = (.*) : user IP = (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)'
    match=re.findall(repattern, data)
    if match:        
        failure['match']=True
        failure['date']=match[0][0]
        failure['device_ip']=match[0][1]
        failure['radius_ip']=match[0][2]
        failure['user']=match[0][3]
        failure['user_ip']=match[0][4]
    return failure    

    

def Readfile(filepath):    
    failures=[]
    with open(filepath) as fp:
        print("Processing file {}".format(filepath))
        line = fp.readline()
        cnt = 1
        while line:           
            failure=checkforFiledLogin(line)
            if failure['match'] == True:
                failures.append(copy.deepcopy(failure))                
            line = fp.readline()            
            cnt += 1
    return failures

def writeLog(failures):    
    with open(csvfile,"w") as f:
        f.write('"Date","Device_ip","radius_ip","user","User_ip"\r\n')
        for user in failures:
            f.write("{},{},{},{},{}\r\n".format(user['date'],user['device_ip'],user['radius_ip'],user['user'],user['user_ip']))

def email(emailfrom,emailto):
    fileToSend = csvfile
    msg = MIMEMultipart()
    msg["From"] = emailfrom
    msg["To"] = ", ".join(emailto)
    msg["Subject"] = "ASA VPN/WebVPN login Failures"
    msg.preamble = "ASA VPN/WebVPN login Failures"

    ctype, encoding = mimetypes.guess_type(fileToSend)
    if ctype is None or encoding is not None:
        ctype = "application/octet-stream"
    maintype, subtype = ctype.split("/", 1)

    if maintype == "text":
        fp = open(fileToSend)
        # Note: we should handle calculating the charset
        attachment = MIMEText(fp.read(), _subtype=subtype)
        fp.close()
    elif maintype == "image":
        fp = open(fileToSend, "rb")
        attachment = MIMEImage(fp.read(), _subtype=subtype)
        fp.close()
    elif maintype == "audio":
        fp = open(fileToSend, "rb")
        attachment = MIMEAudio(fp.read(), _subtype=subtype)
        fp.close()
    else:
        fp = open(fileToSend, "rb")
        attachment = MIMEBase(maintype, subtype)
        attachment.set_payload(fp.read())
        fp.close()
        encoders.encode_base64(attachment)
    attachment.add_header("Content-Disposition", "attachment", filename=filename)
    msg.attach(attachment)

    server = smtplib.SMTP("relay.smhplus.org",25)
    server.sendmail(emailfrom, emailto, msg.as_string())
    server.quit()

def checkemail(email) :
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if(re.fullmatch(regex, email)):
        return True 
    return False

def checkargs(args):
    if args.file == '' or os.path.exists(args.file)==False:
        raise Exception('%s is not a valid file' % args.file)
    if checkemail(args.emailfrom) == False:
        raise Exception('%s is not a valid email' % args.emailfrom)
    if "," in args.emailto:
        for email in args.emailto.splil(','):
            if checkemail(email):
                continue
            else:
                raise Exception('%s is not a valid email' % email)




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Reads the Syslog file from the ASA.')
    parser.add_argument('-f', '--file', default='',help="Syslog file")     
    parser.add_argument('--emailfrom',default='', help="from email address")
    parser.add_argument('--emailto',default='',help="email address split with a comma ")
    args = parser.parse_args()
    checkargs(args)
    failures=Readfile(args.file)   
    writeLog(failures)
    email(args.emailfrom,args.emailto.split(','))
    print(failures)




 