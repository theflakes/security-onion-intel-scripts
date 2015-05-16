#!/usr/bin/python


# Author: Brian Kellogg
# Version: 1.4
#
# Bro Intel file MUST have the below header and it MUST be TAB DELIMITED
# #fields indicator       indicator_type  meta.source     meta.desc       meta.url        meta.do_notice        meta.if_in
#
# This script was written for Bro and OSSEC intel file updates on SecurityOnion


import sys
from subprocess import call
import ConfigParser
import re
import os
from shutil import copy


# string colorization
# from http://korbinin.blogspot.com/2012/10/color-text-output-from-python.html
def hilite(string, status, bold):
    attr = []
    if sys.stdout.isatty():
        if status == 'g':
            # green
            attr.append('32')
        elif status == 'r':
            # red
            attr.append('31')
        elif status == 'y':
            # yellow
            attr.append('33')
        elif status == 'b':
            # blue
            attr.append('34')
        elif status == 'm':
            # magenta
            attr.append('35')
        if bold:
            attr.append('1')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
    else:
        return string


# check if file exists and is writeable
# if file does not exist then ask to create it otherwise exit
def exists_and_writable(intel_file):
    if os.path.isfile(intel_file):
        try:
            with open(intel_file, 'a+') as f:
                f.closed
        except IOError:
            print(hilite("\nFile, %s, is not writeable!\n", "r", True) % intel_file)
            exit(4)
    elif "bro" in intel_file:
        print(hilite("\nBro intel file, %s, does not exist!\n", "r", True) % intel_file)
        create = raw_input("Create intel file (y/n)? ")
        if create == 'y':
            try:
                with open(intel_file, 'w+') as f:
                    f.write('#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.do_notice\tmeta.if_in\n')
            except IOError:
                print(hilite("\nCould not create file!\n", "r", True))
                exit(4)
        else:
            exit(0)
    elif "ossec" in intel_file:
        print(hilite("\nOSSEC intel file, %s, does not exist!\n", "r", True) % intel_file)
        create = raw_input("Create intel file (y/n)? ")
        if create == 'y':
            try:
                with open(intel_file, 'w+') as f:
                    f.closed
            except IOError:
                print(hilite("\nCould not create file!\n", "r", True))
                exit(4)
        else:
            exit(0)


# check if file is executable
def is_executable(program):
    def is_exe(file_path):
        return os.path.isfile(file_path) and os.access(file_path, os.X_OK)

    if is_exe(program):
        return program
    else:
        print(hilite("\n%s is not executable or does not exist!\n", "r", True) % program)
        exit(4)


# clean up duplicate lines in intel files
def remove_duplicate_lines(intel_file):
    # backup intel files before any modifications by script
    copy(intel_file, BACKUP_DIR)
    lines_seen = set()  # holds lines already seen
    with open(intel_file, 'r') as f:
        lines = f.readlines()
    with open(intel_file, 'w') as f:
        for line in lines:
            if line not in lines_seen:  # not a duplicate
                f.write(line)
                lines_seen.add(line)


# clean up OSSEC intel file by removing any complete /24s and adding the three octet equivalent
def ossec_collapse_full_nets(addr, source, intel_file):
    count = 0
    with open(intel_file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if addr in line:
                count += 1
    if count > 255:
        delete_ip(addr, 0, 255, intel_file)
        add_ip(addr, 0, 255, source, "", "", "", "", OSSEC_IP_FILE)


# add IP(s) to intel file
def add_ip(addr, start_ip, end_ip, source, desc, url, notice, if_in, intel_file):
    with open(intel_file, 'a+') as f:
        lines = f.readlines()
        ossec_full_range = addr + ":"
        found = False
        # if adding a /24 to ossec then no need to add each individual IP
        if "ossec" in intel_file:
            for line in lines:
                # did we intially add a /24 to the OSSEC intel file?
                if ossec_full_range in line:
                    print(hilite("%s already exists in %s!", "r", True) % (line, intel_file))
                    found = True
                    break
            if not found and start_ip == 0 and end_ip == 255:
                # remove any existing IPs in this range from the OSSEC intel file
                delete_ip(addr, start_ip, end_ip, intel_file)
                f.write('%s:%s\n' % (addr, source))
                print(hilite("Added %s to %s", "y", True) % (addr, intel_file))
                # since we are adding a /24 lets not trigger the next if clause
                found = True
        if not found:
            for last_octet in range(start_ip, end_ip + 1):
                found = False
                for line in lines:
                    if addr in line:
                        if "ossec" in intel_file:
                            temp = line.split(":")
                        else:
                            temp = line.split('\t')
                        temp = temp[0].split(".")
                        temp = int(temp[3])
                        if last_octet == temp:
                            print(hilite("%s already exists in %s!", "r", True) % (line, intel_file))
                            found = True
                            break
                if "ossec" not in intel_file and not found:
                    f.write('%s\t%s\t%s\t%s\t%s\t%s\t%s\n' %
                            (addr + str(last_octet), "Intel::ADDR", source, desc, url, notice, if_in))
                    print(hilite("Added %s to %s", "y", True) % (addr + str(last_octet), intel_file))
                elif not found:
                    f.write('%s:%s\n' % (addr + str(last_octet), source))
                    print(hilite("Added %s to %s", "y", True) % (addr + str(last_octet), intel_file))
    # lets see if we can take this /24 and rewrite it in the OSSEC short form
    if "ossec" in intel_file:
        ossec_collapse_full_nets(addr, source, intel_file)


# remove IP(s) from intel file
def delete_ip(addr, start_ip, end_ip, intel_file):
    with open(intel_file, 'r') as f:
        lines = f.readlines()
    with open(intel_file, 'w') as f:
        ossec_full_range = addr + ":"
        ossec_add_ip_ranges = False
        for line in lines:
            found = False
            # did we initially add a /24 to the OSSEC intel file?
            if ("ossec" in intel_file) and (ossec_full_range in line):
                print(hilite("Removed %s from %s!", "y", True) % (addr, intel_file))
                # pull out what is after the : so that we can reuse it if we need to add some of the range back in
                source = line.split(":")
                # remove newlines
                source = source[1].rstrip('\n')
                ossec_add_ip_ranges = True
                found = True
            elif addr in line:
                if "ossec" in intel_file:
                    last_octet = line.split(":")
                else:
                    last_octet = line.split('\t')
                last_octet = last_octet[0].split(".")
                last_octet = int(last_octet[3])
                if start_ip <= last_octet <= end_ip:
                    print(hilite("Removed %s from %s!", "y", True) % (addr + str(last_octet), intel_file))
                    found = True
            # write line back to file if not found
            if not found:
                f.write(line)
    # if we removed a /24 from the OSSEC intel file and we need to add back some of that /24 range lets do that
    if ossec_add_ip_ranges and start_ip != 0 and end_ip != 255:
        if start_ip == 0:
            start = end_ip + 1
            end = 255
        elif end_ip == 255:
            start = 0
            end = start_ip - 1
        else:
            start = 0
            end = start_ip - 1
            add_ip(addr, start, end, source, "", "", "", "", OSSEC_IP_FILE)
            start = end_ip + 1
            end = 255
        add_ip(addr, start, end, source, "", "", "", "", OSSEC_IP_FILE)


# choose where Bro is to look for the intel
def get_if_in():
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
def get_info():
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
    if_in = get_if_in()
    return source, desc, url, notice, if_in


# get the information to add or remove intel then perform the specified operation
def misc_intel(op, header, type, intel_file):
    print("\n%s" % header)
    print("----------------------------")
    intel = raw_input("Intel? ")
    source, desc, url, notice, ifIn = get_info()
    if op == "add":
        add_misc_intel(type, intel, intel_file, source, desc, url, notice, ifIn)
    else:
        delete_misc_intel(intel, intel_file)
    return intel


# add all other types of intel
def add_misc_intel(intel_type, intel, intel_file, source, desc, url, notice, if_in):
    with open(intel_file, 'a+') as f:
        lines = f.readlines()
        # Lets see if this intel is already in the file
        for line in lines:
            if intel in line:
                print(hilite("%s already exists in file!", "r", True) % intel)
                # if we get a match then exit
                return
        # write line to file if not found
        # how we write to the file is dependent on if it is an OSSEC intel file or a Bro intel file
        if "ossec" in intel_file:
            f.write('%s:drc\n' % intel)
        else:
            f.write('%s\t%s\t%s\t%s\t%s\t%s\t%s\n' % (intel, intel_type, source, desc, url, notice, if_in))
        print(hilite("Added %s to %s", "y", True) % (intel, intel_file))


# remove misc intel type
def delete_misc_intel(intel, intel_file):
    with open(intel_file, 'r') as f:
        lines = f.readlines()
    # open intel file for writing
    with open(intel_file, 'w') as f:
        found = False
        for line in lines:
            # skip matching line we want to remove
            if intel in line:
                found = True
                print(hilite("Removed %s from %s!", "y", True) % (intel, intel_file))
                continue
            # write line back to file if not a match
            f.write(line)
    if not found:
        print(hilite("%s not found int %s", "y", True) % (intel, intel_file))


# Get user input and run correct function to add or remove intel IP
def do_ip(header, question, single_ip, add):
    print("\n%s" % header)
    print("----------------------------")
    addr = raw_input("First three octets including the trailing . ? ")
    # need to convert beginning IP to int for comparison
    start_ip = int(raw_input(question))
    # if singleIP is TRUE then then set endIP = begIP
    if single_ip:
        end_ip = start_ip
    else:
        # need to convert ending IP to int for comparison
        end_ip = int(raw_input("Last IP in last octet? "))
    # is the IP information valid, if not return to main menu
    if start_ip < 0 or end_ip > 255 or not (re.match(IP_REGEX, addr)):
        print(hilite("\n\nInvalid IP information.", "r", True))
        return
    if add:
        source, desc, url, notice, if_in = get_info()
    print(hilite("\n------------RESULTS---------------", "y", True))
    if add:
        add_ip(addr, start_ip, end_ip, source, desc, url, notice, if_in, BRO_INTEL_FILE)
        add_ip(addr, start_ip, end_ip, source, desc, url, notice, if_in, OSSEC_IP_FILE)
    else:
        delete_ip(addr, start_ip, end_ip, BRO_INTEL_FILE)
        delete_ip(addr, start_ip, end_ip, OSSEC_IP_FILE)
    call(OSSEC_MAKELISTS)


def main_menu():
    cont = True
    while cont:
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
            do_ip("\nAdd single intel IP:", "Last octet? ", True, True)
        elif ans == "2":
            do_ip("\nAdd range of intel IPs:", "First IP in last octet? ", False, True)
        elif ans == "3":
            do_ip("\nRemove single intel IP:", "Last octet? ", True, False)
        elif ans == "4":
            do_ip("\nRemove range of intel IPs:", "First IP in last octet? ", False, False)
        elif ans == "5":
            misc_intel("add", "\nAdd URL:", "Intel::URL", BRO_INTEL_FILE)
        elif ans == "6":
            misc_intel("rem", "\nRemove URL:", "", BRO_INTEL_FILE)
        elif ans == "7":
            misc_intel("add", "\nAdd software:", "Intel::SOFTWARE", BRO_INTEL_FILE)
        elif ans == "8":
            misc_intel("rem", "\nRemove software:", "", BRO_INTEL_FILE)
        elif ans == "9":
            misc_intel("add", "\nAdd Email:", "Intel::EMAIL", BRO_INTEL_FILE)
        elif ans == "10":
            misc_intel("rem", "\nRemove Email:", "", BRO_INTEL_FILE)
        elif ans == "11":
            intel = misc_intel("add", "\nAdd domain:", "Intel::DOMAIN", BRO_INTEL_FILE)
            add_misc_intel("", intel, OSSEC_DNS_FILE, "", "", "", "", "")
            call(OSSEC_MAKELISTS)
        elif ans == "12":
            intel = misc_intel("rem", "\nRemove domain:", "", BRO_INTEL_FILE)
            delete_misc_intel(intel, OSSEC_DNS_FILE)
            call(OSSEC_MAKELISTS)
        elif ans == "13":
            intel = misc_intel("add", "\nAdd username:", "Intel::USER_NAME", BRO_INTEL_FILE)
            add_misc_intel("", intel, OSSEC_USERS_FILE, "", "", "", "", "")
            call(OSSEC_MAKELISTS)
        elif ans == "14":
            intel = misc_intel("rem", "\nRemove username:", "", BRO_INTEL_FILE)
            delete_misc_intel(intel, OSSEC_USERS_FILE)
            call(OSSEC_MAKELISTS)
        elif ans == "15":
            misc_intel("add", "\nAdd file hash:", "Intel::FILE_HASH", BRO_INTEL_FILE)
        elif ans == "16":
            misc_intel("rem", "\nRemove file hash:", "", BRO_INTEL_FILE)
        elif ans == "17":
            misc_intel("add", "\nAdd file name:", "Intel::FILE_NAME", BRO_INTEL_FILE)
        elif ans == "18":
            misc_intel("rem", "\nRemove file name:", "", BRO_INTEL_FILE)
        elif ans == "19":
            misc_intel("add", "\nAdd Cert hash:", "Intel::CERT_HASH", BRO_INTEL_FILE)
        elif ans == "20":
            misc_intel("rem", "\nRemove Cert hash:", "", BRO_INTEL_FILE)
        elif ans == "q":
            exit(0)
        else:
            print(hilite("\nInvalid input!", "r", True))


def main():
    usage = """
        usage: %prog

        Update the modIntel.conf file to point to your Bro and OSSEC intel files.

        The modIntel.conf file must reside in the same directory or
        modify this script with the location you placed it in.

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

        The script, before performing any other action on intel files, will backup all intel files
        to the specified location in modIntel.conf.

        The script will also parse all intel files for duplicates upon startup.

        The script does its best to honor OSSEC's ability to specify IPs at the octet boundaries but only for /24s.
        Logic is not included for /8s or /16s.
        """
    if len(sys.argv) > 1:
        print(hilite("\n%s", "r", True) % usage)
    # regex to match first three octets of IP including trailing "."
    global IP_REGEX, BRO_INTEL_FILE, OSSEC_IP_FILE, OSSEC_DNS_FILE, OSSEC_MAKELISTS, OSSEC_USERS_FILE, BACKUP_DIR
    IP_REGEX = re.compile("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.$")
    # globals to hold Bro and OSSEC intel file locations
    # read in configs
    config = ConfigParser.ConfigParser()
    config.readfp(open(r'modIntel.conf'))
    BRO_INTEL_FILE = config.get('files', 'bro')
    OSSEC_IP_FILE = config.get('files', 'ossecIP')
    OSSEC_DNS_FILE = config.get('files', 'ossecDNS')
    OSSEC_USERS_FILE = config.get('files', 'ossecUsers')
    OSSEC_MAKELISTS = config.get('files', 'ossecMLISTS')
    BACKUP_DIR = config.get('files', 'backupDir')
    if not os.access(BACKUP_DIR, os.W_OK):
        print(hilite("\n%s is not writeable or does not exist!\nPlease check your configuration.\n", "r", True) % BACKUP_DIR)
        exit(4)
    check_files = BRO_INTEL_FILE, OSSEC_IP_FILE, OSSEC_DNS_FILE, OSSEC_USERS_FILE
    for check in check_files:
        exists_and_writable(check)
        remove_duplicate_lines(check)
    # is the OSSEC CDB compiler there and executable
    is_executable(OSSEC_MAKELISTS)
    # compile OSSEC CDBs in case they were modified by the above duplicate checks
    call(OSSEC_MAKELISTS)
    # goto main menu
    main_menu()


if __name__ == '__main__':
    main()
