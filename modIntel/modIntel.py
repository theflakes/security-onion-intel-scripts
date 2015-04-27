#!/usr/bin/python

#
# Author: Brian Kellogg
# Version: 1.4
#
# Bro Intel file MUST have the below header and it MUST be TAB DELIMITED
# #fields indicator       indicator_type  meta.source     meta.desc       meta.url        meta.do_notice        meta.if_in
#
# This script was written for Bro and OSSEC intel file updates on SecurityOnion
#


import sys
from subprocess import call
from optparse import OptionParser
import ConfigParser
import re
import os
import stat
from shutil import copy

# regex to match first three octets of IP including trailing "."
regIP = re.compile("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.$")


# string colourizations
# from http://korbinin.blogspot.com/2012/10/color-text-output-from-python.html
def hilite(string, status, bold):
    attr = []
    if(sys.stdout.isatty()):
        if status=='g':
            # green
            attr.append('32')
        elif status=='r':
            # red
            attr.append('31')
        elif status=='y':
            # yellow
            attr.append('33')
        elif status=='b':
            # blue
            attr.append('34')
        elif status=='m':
            # magenta
            attr.append('35')
        if bold:
            attr.append('1')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
    else:
        return(string)


# check if file exists and is writeable
# if file is does not exist then ask to create it otherwise exit
def EandW(intelFile):
        if os.path.isfile(intelFile):
                try:
                        f = open(intelFile, 'a+')
                        f.close()
                except:
                        print(hilite("\nFile, %s, is not writeable!\n", "r", True) % (intelFile))
                        exit(4)
        elif "bro" in intelFile:
                print(hilite("\nBro intel file, %s, does not exist!\n", "r", True) % (intelFile))
                create = raw_input("Create intel file (y/n)? ")
                if create == 'y':
                        try:
                                f = open(intelFile, 'w+')
                                f.write('#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.do_notice\tmeta.if_in\n')
                                f.close
                        except:
                                print(hilite("\nCould not create file!\n", "r", True))
                                exit(4)
                else:
                        exit(0)
        else:
                print(hilite("\nOSSEC intel file, %s, does not exist!\n", "r", True) % (intelFile))
                create = raw_input("Create intel file (y/n)? ")
                if create == 'y':
                        try:
                                f = open(intelFile, 'w+')
                                f.close
                        except:
                                print(hilite("\nCould not create file!\n", "r", True))
                                exit(4)
                else:
                        exit(0)


# check if file is executable
def isEXE(program):
        def is_exe(fpath):
                return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

        if is_exe(program):
                return program
        else:
                print(hilite("\n%s is not executable or does not exist!\n", "r", True) %(program))
                exit(4)


# clean up duplicate lines in intel files
def cleanDups(intelFile):
        # backup intel files before any modifications by script
        copy(intelFile, backupDir)
        lines_seen = set() # holds lines already seen
        f = open(intelFile,"r")
        lines = f.readlines()
        f.close
        f = open(intelFile,"w")
        for line in lines:
                if line not in lines_seen: # not a duplicate
                        f.write(line)
                        lines_seen.add(line)
        f.close()


# clean up OSSEC intel file by removing any complete /24s and adding the three octet equivelant
def cleanOssec(addr, source, intelFile):
        count = 0
        f = open(intelFile,"r")
        lines = f.readlines()
        for line in lines:
                if addr in line:
                        count += 1
        f.close
        if count > 255:
                remIP(addr, 0, 255, intelFile)
                addIP(addr, 0, 255, source, "", "", "", "", ossecIP)


# add IP(s) to intel file
def addIP(addr, begIP, endIP, source, desc, url, notice, ifIn, intelFile):
        # Open file for reading and appending
        f = open(intelFile,"a+")
        lines = f.readlines()
        ossecFullRange = addr + ":"
        found = False
        # if adding a /24 to ossec then no need to add each individual IP
        if "ossec" in intelFile:
                for line in lines:
                        # did we intially add a /24 to the OSSEC intel file?
                        if ossecFullRange in line:
                                print(hilite("%s already exists in %s!", "r", True) % (line, intelFile))
                                found = True
                                break
                if not found and begIP == 0 and endIP == 255:
                        # remove any existing IPs in this range from the OSSEC intel file
                        remIP(addr, begIP, endIP, intelFile)
                        f.write('%s:%s\n' % (addr, source))
                        print(hilite("Added %s to %s", "y", True) % (addr, intelFile))
                        # since we are adding a /24 lets not trigger the next if clause
                        found = True
        if not found:
                for lastOctet in range(begIP,endIP + 1):
                        found = False
                        for line in lines:
                                if addr in line:
                                        if "ossec" in intelFile:
                                                temp = line.split(":")
                                        else:
                                                temp = line.split('\t')
                                        temp = temp[0].split(".")
                                        temp = int(temp[3])
                                        if lastOctet == temp:
                                                print(hilite("%s already exists in %s!", "r", True) % (line, intelFile))
                                                found = True
                                                break
                        if "ossec" not in intelFile and not found:
                                f.write('%s\t%s\t%s\t%s\t%s\t%s\t%s\n' % (addr + str(lastOctet),"Intel::ADDR",source,desc,url,notice,ifIn))
                                print(hilite("Added %s to %s", "y", True) % (addr + str(lastOctet), intelFile))
                        elif not found:
                                f.write('%s:%s\n' % (addr + str(lastOctet), source))
                                print(hilite("Added %s to %s", "y", True) % (addr + str(lastOctet), intelFile))
                # lets see if we can take this /24 and rewrite it in the OSSEC short form
                if "ossec" in intelFile:
                        cleanOssec(addr, source, intelFile)
        f.close()


# remove IP(s) from intel file
def remIP(addr, begIP, endIP, intelFile):
        # Open Bro intel file for appending
        f = open(intelFile,"r")
        lines = f.readlines()
        f.close()
        # open intel file for writing
        f = open(intelFile,"w")
        ossecFullRange = addr + ":"
        ossec_addIP_Ranges = False
        for line in lines:
                found = False
                # did we intially add a /24 to the OSSEC intel file?
                if ("ossec" in intelFile) and (ossecFullRange in line):
                        print(hilite("Removed %s from %s!", "y", True) % (addr, intelFile))
                        # pull out what is after the : so that we can reuse it if we need to add some of the range back in
                        source = line.split(":")
                        # remove newlines
                        source = source[1].rstrip('\n')
                        ossec_addIP_Ranges = True
                        found = True
                elif addr in line:
                        if "ossec" in intelFile:
                                lastOctet = line.split(":")
                        else:
                                lastOctet = line.split('\t')
                        lastOctet = lastOctet[0].split(".")
                        lastOctet = int(lastOctet[3])
                        if lastOctet >= begIP and lastOctet <= endIP:
                                print(hilite("Removed %s from %s!", "y", True) % (addr + str(lastOctet), intelFile))
                                found = True
                # write line back to file if not found
                if not found:
                        f.write(line)
        f.close()
        # if we removed a /24 from the OSSEC intel file and we need to add back some of that /24 range lets do that
        if ossec_addIP_Ranges and begIP != 0 and endIP != 255:
                if begIP == 0:
                        start = endIP + 1
                        end = 255
                elif endIP == 255:
                        start = 0
                        end = begIP - 1
                else:
                        start = 0
                        end = begIP - 1
                        addIP(addr, start, end, source, "", "", "", "", ossecIP)
                        start = endIP + 1
                        end = 255
                addIP(addr, start, end, source, "", "", "", "", ossecIP)


# choose where to look for the intel
def getIfIn():
        cont = True
        while cont:
                print("""
                Choose where to look for intel:
                Hit enter for default of (-)
                ********************************
                1. Conn::IN_ORIG
                2. Conn::IN_RESP
                3. Files::IN_HASH
                4. Files::IN_NAME
                5. DNS::IN_REQUEST
                6. DNS::IN_RESPONSE
                7. HTTP::IN_HOST_HEADER
                8. HTTP::IN_REFERRER_HEADER
                9. HTTP::IN_USER_AGENT_HEADER
                10. HTTP::IN_X_FORWARDED_FOR_HEADER
                11. HTTP::IN_URL
                12. SMTP::IN_MAIL_FROM
                13. SMTP::IN_RCPT_TO
                14. SMTP::IN_FROM
                15. SMTP::IN_TO
                16. SMTP::IN_RECEIVED_HEADER
                17. SMTP::IN_REPLY_TO
                18. SMTP::IN_X_ORIGINATING_IP_HEADER
                19. SMTP::IN_MESSAGE
                20. SSL::IN_SERVER_CERT
                21. SSL::IN_CLIENT_CERT
                22. SSL::IN_SERVER_NAME
                23. SMTP::IN_HEADER
                24. Leave Blank

                """)
                ans = raw_input("Choice (-)? ")
                if ans == "1":
                        return "Conn::IN_ORIG"
                elif ans == "2":
                        return "Conn::IN_RESP"
                elif ans == "3":
                        return "Files::IN_HASH"
                elif ans == "4":
                        return "Files::IN_NAME"
                elif ans == "5":
                        return "DNS::IN_REQUEST"
                elif ans == "6":
                        return "DNS::IN_RESPONSE"
                elif ans == "7":
                        return "HTTP::IN_HOST_HEADER"
                elif ans == "8":
                        return "HTTP::IN_REFERRER_HEADER"
                elif ans == "9":
                        return "HTTP::IN_USER_AGENT_HEADER"
                elif ans == "10":
                        return "HTTP::IN_X_FORWARDED_FOR_HEADER"
                elif ans == "11":
                        return "HTTP::IN_URL"
                elif ans == "12":
                        return "SMTP::IN_MAIL_FROM"
                elif ans == "13":
                        return "SMTP::IN_RCPT_TO"
                elif ans == "14":
                        return "SMTP::IN_FROM"
                elif ans == "15":
                        return "SMTP::IN_TO"
                elif ans == "16":
                        return "SMTP::IN_RECEIVED_HEADER"
                elif ans == "17":
                        return "SMTP::IN_REPLY_TO"
                elif ans == "18":
                        return "SMTP::IN_X_ORIGINATING_IP_HEADER"
                elif ans == "19":
                        return "SMTP::IN_MESSAGE"
                elif ans == "20":
                        return "SSL::IN_SERVER_CERT"
                elif ans == "21":
                        return "SSL::IN_CLIENT_CERT"
                elif ans == "22":
                        return "SSL::IN_SERVER_NAME"
                elif ans == "23":
                        return "SMTP::IN_HEADER"
                elif ans == "24":
                        return "-"
                else:
                        return "-"


# get all the info needed to add the intel
def getInfo():
        desc = raw_input("Description? ")
        if not desc:
                desc = "-"
        source = raw_input("Source (drc)? ")
        if not source:
                source = "drc"
        url = raw_input("URL? ")
        if not url:
                url = "-"
        notice = raw_input("Do notice (T)? ")
        notice = notice.upper()
        if notice != "T" or notice != "F":
                notice = "T"
        ifIn = getIfIn()
        return (source, desc, url, notice, ifIn)


# get the information to add or remove intel then perform the specified operation
def miscIntel(op, header, type, intelFile):
        print("\n%s" % (header))
        print("----------------------------")
        intel = raw_input("Intel? ")
        source, desc, url, notice, ifIn = getInfo()
        if op == "add":
                addMisc(type, intel, intelFile, source, desc, url, notice, ifIn)
        else:
                remMisc(intel, intelFile)
        return intel


# add all other types of intel
def addMisc(type, intel, intelFile, source, desc, url, notice, ifIn):
        f = open(intelFile,"a+")
        lines = f.readlines()
        # Lets see if this intel is already in the file
        for line in lines:
                if intel in line:
                        print(hilite("%s already exists in file!", "r", True) % (intel))
                        # if we get a match then exit
                        return
        # write line to file if not found
        # how we write to the file is dependent on if it is an OSSEC intel file or a Bro intel file
        if "ossec" in intelFile:
                f.write('%s:drc\n' % (intel))
        else:
                f.write('%s\t%s\t%s\t%s\t%s\t%s\t%s\n' % (intel,type,source,desc,url,notice,ifIn))
        print(hilite("Added %s to %s", "y", True) % (intel, intelFile))
        f.close()


# remove misc intel type
def remMisc(intel, intelFile):
        f = open(intelFile,"r")
        lines = f.readlines()
        f.close()
        # open intel file for writing
        f = open(intelFile,"w")
        found = False
        for line in lines:
                # skip matching line we want to remove
                if intel in line:
                        found = True
                        print(hilite("Removed %s from %s!", "y", True) % (intel, intelFile))
                        continue
                # write line back to file if not a match
                f.write(line)
        if not found:
                print(hilite("%s not found int %s", "y", True) % (intel, intelFile))
        f.close()


# Get user input and run correct function to add or remove intel IP
def doIP(header, begText, singleIP, add):
        print("\n%s" % (header))
        print("----------------------------")
        addr = raw_input("First three octets including the trailing . ? ")
        # need to convert beginning IP to int for comparison
        begIP = int(raw_input(begText))
        # if singleIP is TRUE then then set endIP = begIP
        if singleIP:
                endIP = begIP
        else:
                # need to convert ending IP to int for comparison
                endIP = int(raw_input("Last IP in last octet? "))
        # is the IP information valid, if not return to main menu
        if (begIP < 0 or endIP > 255 or not(re.match(regIP,addr))):
                print(hilite("\n\nInvalid IP information.", "r", True))
                return
        if add:
                source, desc, url, notice, ifIn = getInfo()
        print(hilite("\n------------RESULTS---------------", "y", True))
        if add:
                addIP(addr, begIP, endIP, source, desc, url, notice, ifIn, broIntel)
                addIP(addr, begIP, endIP, source, desc, url, notice, ifIn, ossecIP)
        else:
                remIP(addr, begIP, endIP, broIntel)
                remIP(addr, begIP, endIP, ossecIP)
        call(ossecMLISTS)


def mainMenu():
        cont = True
        while cont:
                # triple quotes = multi-line print
                print("""

                Intel Update:
                ##############################
                1. Add single intel IP
                2. Add range of intel IPs
                3. Remove single intel IP
                4. Remove range of intel IPs
                5. Add URL
                6. Remove URL
                7. Add Software
                8. Remove Software
                9. Add Email
                10. Remove Email
                11. Add Domain
                12. Remove Domain
                13. Add Username
                14. Remove Username
                15. Add File Hash
                16. Remove File Hash
                17. Add File Name
                18. Remove File Name
                19. Add Cert Hash
                20. Remove Cert Hash

                q. Quit
                ##############################
                """)
                ans = raw_input("Choice? ")
                if ans == "1":
                        doIP("\nAdd single intel IP:", "Last octet? ", True, True)
                elif ans == "2":
                        doIP("\nAdd range of intel IPs:", "First IP in last octet? ", False, True)
                elif ans == "3":
                        doIP("\nRemove single intel IP:", "Last octet? ", True, False)
                elif ans == "4":
                        doIP("\nRemove range of intel IPs:", "First IP in last octet? ", False, False)
                elif ans == "5":
                        miscIntel("add", "\nAdd URL:", "Intel::URL", broIntel)
                elif ans == "6":
                        miscIntel("rem", "\nRemove URL:", "", broIntel)
                elif ans == "7":
                        miscIntel("add", "\nAdd software:", "Intel::SOFTWARE", broIntel)
                elif ans == "8":
                        miscIntel("rem", "\nRemove software:", "", broIntel)
                elif ans == "9":
                        miscIntel("add", "\nAdd Email:", "Intel::EMAIL", broIntel)
                elif ans == "10":
                        miscIntel("rem", "\nRemove Email:", "", broIntel)
                elif ans == "11":
                        intel = miscIntel("add", "\nAdd domain:", "Intel::DOMAIN", broIntel)
                        addMisc("", intel, ossecDNS, "", "", "", "", "")
                        call(ossecMLISTS)
                elif ans == "12":
                        intel = miscIntel("rem", "\nRemove domain:", "", broIntel)
                        remMisc(intel, ossecDNS)
                        call(ossecMLISTS)
                elif ans == "13":
                        intel = miscIntel("add", "\nAdd username:", "Intel::USER_NAME", broIntel)
                        addMisc("", intel, ossecUsers, "", "", "", "", "")
                        call(ossecMLISTS)
                elif ans == "14":
                        intel = miscIntel("rem", "\nRemove username:", "", broIntel)
                        remMisc(intel, ossecUsers)
                        call(ossecMLISTS)
                elif ans == "15":
                        miscIntel("add", "\nAdd file hash:", "Intel::FILE_HASH", broIntel)
                elif ans == "16":
                        miscIntel("rem", "\nRemove file hash:", "", broIntel)
                elif ans == "17":
                        miscIntel("add", "\nAdd file name:", "Intel::FILE_NAME", broIntel)
                elif ans == "18":
                        miscIntel("rem", "\nRemove file name:", "", broIntel)
                elif ans == "19":
                        miscIntel("add", "\nAdd Cert hash:", "Intel::CERT_HASH", broIntel)
                elif ans == "20":
                        miscIntel("rem", "\nRemove Cert hash:", "", broIntel)
                elif ans == "q":
                        exit(0)
                else:
                        print(hilite("\nInvalid input!", "r", True))


def main():
        usage = """
        usage: %prog

        Update the modIntel.conf file to point to your Bro and OSSEC intel files.

        The modIntel.conf file must reside in the same directory or modify this script with the location you placed it in.

        Header of the intel file must be:
        #fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.do_notice\tmeta.if_in
        Remember Bro intel files MUST be tab delimited!!!

        Any Bro intel file must be loaded into Bro to be used.
        Example, add below to /opt/bro/share/bro/site/local.bro in order to load the your intel1.txt custom file:
                redef Intel::read_files += {
                        "/opt/bro/share/bro/policy/intel1.txt",
                };

        Bro adds new intel but does not remove without a restart:
                sudo broctl install
                sudo broctl restart
                or sudo nsme_sensor_ps-restart --only-bro

        The script will also run the ossec-makelists command to compile any updated CDB files.

        The script, before performing any other action on intel files, will backup all intel files to the specified location in modIntel.conf.
        The script will also parse all intel files for duplicates upon startup.
        The script does its best to honor OSSEC's ability to specify IPs at the octet boundaries but only for /24s.  Logic is not included for /8s or /16s.
        """
        if len(sys.argv) > 1:
                print(hilite("\n%s", "r", True) % usage)
        # read in configs
        config = ConfigParser.ConfigParser()
        config.readfp(open(r'modIntel.conf'))
        # globals to hold Bro and OSSEC intel file locations
        global broIntel, ossecIP, ossecDNS, ossecMLISTS, ossecUsers, backupDir
        broIntel = config.get('files', 'bro')
        ossecIP = config.get('files', 'ossecIP')
        ossecDNS = config.get('files', 'ossecDNS')
        ossecUsers = config.get('files', 'ossecUsers')
        ossecMLISTS = config.get('files', 'ossecMLISTS')
        backupDir = config.get('files', 'backupDir')
        if not os.access(backupDir, os.W_OK):
                print(hilite("\n%s is not writeable or does not exist!\nPlease check your configuration.\n", "r", True) % (backupDir))
                exit(4)
        # check if files exists and is writeable
        EandW(broIntel)
        EandW(ossecIP)
        EandW(ossecDNS)
        EandW(ossecUsers)
        # is the OSSEC CDB compiler there and executable
        isEXE(ossecMLISTS)
        # lets check all intel files for duplicates and remove them
        cleanDups(broIntel)
        cleanDups(ossecIP)
        cleanDups(ossecDNS)
        cleanDups(ossecUsers)
        # compile OSSEC CDBs in case they were modified by the above duplicate checks
        call(ossecMLISTS)
        # goto main menu
        mainMenu()


if __name__ == '__main__':
        main()
