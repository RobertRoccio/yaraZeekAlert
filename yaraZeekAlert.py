#!/usr/bin/python3
# Name: yaraZeekAlert.py

# Original Author: David Bernal Michelena - SCILabs, 2019
# Updated and Adapted by: Robert Roccio
# License: CREATIVE COMMONS LICENSE BY-NC https://creativecommons.org/licenses/by-nc/4.0/

# Description:
# This script scans the files extracted by Zeek with YARA rules located on the rules folder on a Linux based Zeek sensor, if there is a match it sends email alerts to the email address specified in the mailTo parameter on yaraAlert.conf file. The alert includes network context of the file transfer and attaches the suspicious file if it is less than 10 MB. Alerted files are copied locally to the alerted files folder.

import subprocess
import os
import time
import sys
import hashlib
import smtplib
import glob
from base64 import encode,decode
from email.mime.multipart import MIMEMultipart
from email.message import EmailMessage
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

alertedFilesFolder=os.getcwd() + "/alerted-files"
extractedFilePath=os.getcwd() + "/extracted-files"
yaraAlertConfigFile=os.getcwd() + "/yaraAlert.conf"
yaraRulesPath=os.getcwd() + "/yara-rules"
actionsLogPath=os.getcwd() + "/logs/action.log"
sevenZipCommand = "/bin/7za"

if not os.path.isfile(yaraAlertConfigFile):
	print("file does not exist: " + yaraAlertConfigFile)
	sys.exit(1)

with open(yaraAlertConfigFile,"r") as f:
	for line in f:
		lineLst = line.strip("\n").split("=")
		if lineLst[0] in "mailUsername":
			mailUsername = lineLst[1]
		elif lineLst[0] in "mailPassword":
			mailPassword = lineLst[1]
		elif lineLst[0] in "mailServer":
			mailServer = lineLst[1]
		elif lineLst[0] in "mailPort":
			mailPort = lineLst[1]
		elif lineLst[0] in "mailDisplayFrom":
			mailDisplayFrom = lineLst[1]
		elif lineLst[0] in "mailTo":
			mailTo = lineLst[1]
def hashes(fname):
	md5 = hashlib.md5(open(fname,'rb').read()).hexdigest()
	sha1 = hashlib.sha1(open(fname,'rb').read()).hexdigest()
	sha256 = hashlib.sha256(open(fname,'rb').read()).hexdigest()
	return [md5,sha1,sha256]

def searchContext(searchPath, pattern,archived):
		flog = open(actionsLogPath,"w+")
		flog.write("searching for pattern: " + pattern + " in " + searchPath)

		out = ""
		currentLogPath="/usr/local/zeek/logs/current"
		
		if not archived:
			files = glob.glob(searchPath + "/*.log")
		else:
			files = glob.glob(searchPath + "/*.log.gz")

		for f in files:
			flog.write("searching in " + f)
			if not archived:
				command = "/bin/cat " + f + " | /usr/local/zeek/bin/zeek-cut -d | grep " + pattern + " "
				flog.write("command :" + command)
			else:
				command = "/bin/zgrep " + pattern + " " + f
				flog.write("command :" + command)
				print(command)
			try:
				flog.write("before appending \n" + out)
				out += subprocess.check_output(command, shell=True)
				flog.write("after appending \n" + out)
			except:
				pass

		print("context found in path: " + searchPath)
		flog.write("context found in path: \n" + searchPath)

		if out =="":
			out = "Context not found in current logs \n"

		print(out)
		flog.write("output: " + out)
		return out

def sendAlertEmail(message,fromaddr,recipient,filepath,context):
	toaddr = recipient

	msg = EmailMessage()
	msg['From'] = fromaddr
	msg['To'] = recipient
	msg['Subject'] = "YARA Alert"

	body = "alerted rules: " + str(message[0]) + "\n"
	body = body + "filepath: " + str(message[1]) + "\n"
	body = body + "md5sum : " + str(message[2]) + "\n"
	body = body + "sha1sum: " + str(message[3]) + "\n"
	body = body + "sha256sum: " + str(message[4]) + "\n\n"

	
	filename = filepath.split("/")[-1]	
	generatedZip = alertedFilesFolder + "/" + filename + ".zip"
	print("generatedZip: " + generatedZip)
	
	if os.path.isfile(generatedZip):
		os.remove(generatedZip)

	rc = subprocess.call([sevenZipCommand, 'a', '-pinfected', '-y', generatedZip, filepath])

	body = body + "saved Zip file: " + generatedZip + "\n\n"
	body = body + "context: " + context + "\n"

	filesize = os.path.getsize(generatedZip)
	
	print(body)
	
	print("filepath: " + filepath + " size: " + str(filesize))
	if os.path.getsize(generatedZip) < 10000000:
		part = MIMEBase('application', "zip")
		part.set_payload(open(generatedZip, "rb").read())
		encoders.encode_base64(part)
		part.add_header('Content-Disposition', 'attachment; filename="' + filename + ".zip")
		msg.attach(part)
	else:
		body = body + "File is too big for the attachment"

	msg.set_content(body)
	server = smtplib.SMTP_SSL(mailServer,mailPort)
	server.ehlo()

	# Base64 encoding prevents issues with special characters with passwords/usernames
	mailUsernameEncoded = base664.encode(mailUsername)
	mailPasswordEncoded = base64.encode(mailPassword)
	server.login(base64.decode(mailUsernameEncoded),base64.decode(mailPasswordEncoded))
	server.send_message(msg)
	server.quit()
	
fout = open("/tmp/yaraAllRules","wb")

print(extractedFilePath)
yaraRules = subprocess.check_output("find " + yaraRulesPath + " -name '*.yar' -exec cat {} + ", shell=True)

fout.write(yaraRules)
fout.close()

start = time.time()
#scanOutput =  subprocess.check_output("yara -r /tmp/yaraAllRules " + extractedFilePath, shell=True)
scanOutput = subprocess.check_output("yara -r /tmp/yaraAllRules " + extractedFilePath + " -d extension=\"noext\" -d filename=\"nofilename\" -d filepath=\"nofilepath\" -d filetype=\"nofiletype\"", shell=True)

end = time.time()

print("Run time: " + str((end - start)))
i=0
scanOutput = scanOutput.decode().split('\n')

filesWithAlerts = {}

for line in scanOutput:
	if not "warning" in line and len(line) > 10:
		rule,filepath = line.strip().split(' ')

		# If the file exists, it obtains the file hash
		if filepath in filesWithAlerts.keys():
			filesWithAlerts[filepath].append(rule)		
		else:
			filesWithAlerts[filepath] = [rule]

for filepath, matchedRules in filesWithAlerts.items():
	print("filepath: " + filepath + " v: " +  str(matchedRules))
	entry = [str(matchedRules),filepath] + hashes(filepath)
	try:
		print("send alert email")
		pattern = filepath.split("/")[-1].split("-")[-1].split(".")[-2]
		
		context = searchContext("/usr/local/zeek/logs/current", pattern,archived=False)

		if context == "":
			print("No additional context was found, searching on the historical log.")
		else:
			print(context)

		sendAlertEmail(entry,mailDisplayFrom,mailTo,filepath,context)
	except Exception as e:
		print(e)

files = glob.glob(extractedFilePath + "/*")

for f in files:
	os.remove(f)
