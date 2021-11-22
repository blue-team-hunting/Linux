# Linux Secure Log SSH Parser
# Developed by Greg Wood
# version 0.0.1 (2021-08-30)


import argparse
import datetime

class SecureLog:
    pid = ""
    start_raw_event = ""
    term_raw_event = ""
    start_timestamp = ""
    end_timestamp = ""
    hostname = ""
    process_name = ""
    start_notes = ""
    term_notes = ""
    user_name = ""
    ip_address = ""
    source_port = ""
    isFailedLogin = True
    isSessTerm = False
    fails = ["Invalid", "Failed"]
    successes = ["Accepted"]
    terminations = ["Disconnected", "Received", "Connection"]
    pam = ["pam_unix", "pam_succeed_if", "PAM"]

    def merge(self, new_event):
        if not new_event.isSessTerm:
            if not self.start_raw_event:
                self.start_raw_event = new_event.start_raw_event
            else:
                self.start_raw_event = self.start_raw_event + " | " + new_event.start_raw_event
            if not self.hostname:
                self.hostname = new_event.hostname
            if not self.user_name:
                self.user_name = new_event.user_name
            if not self.ip_address:
                self.ip_address = new_event.ip_address
            if not self.source_port:
                self.source_port = new_event.source_port
        elif new_event.isSessTerm:
            if not self.term_raw_event:
                self.term_raw_event = new_event.term_raw_event
            else:
                self.term_raw_event = self.term_raw_event + " | " + new_event.term_raw_event
            if not self.end_timestamp:
                self.end_timestamp = new_event.end_timestamp
            self.isSessTerm = True

        return self

    def process_timestamp(self, pl, fn):
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        if len(pl[1]) == 1:
            day = "0" + pl[1]
        else:
            day = pl[1]
        hours = pl[2].split(":")[0]
        minutes = pl[2].split(":")[1]
        seconds = pl[2].split(":")[2]
        month = str(months.index(pl[0]) + 1)
        if len(month) == 1:
            month = "0" + month
        year = str(datetime.date.today()).split("-")[0]

        test = fn.split("-")[1][0:8]
        isFnArchived = False
        for i in test:
            if i in "0123456789":
                pass
            else:
                break
            isFnArchived = True

        if isFnArchived:
            year = test[0:4]

        return year + "-" + month + "-" + day + " " + hours + ":" + minutes + ":" + seconds

    def issupportedEvent(self, m_list):
        if m_list[0] in self.fails or m_list[0] in self.successes or m_list[0] in self.terminations:
            return True
        elif m_list[0][0:8] in self.pam or m_list[0][0:14] in self.pam or m_list[0][0:4] in self.pam:
            return True
        else:
            return False

    def process_notes(self):
        if self.isFailedLogin:
            self.start_notes += "Failed SSH login for: " + self.user_name + " from " + self.ip_address + ":" + self.source_port + ". Session terminated at: " + self.end_timestamp
            self.term_notes += "Failed SSH login for: " + self.user_name + " from " + self.ip_address + ":" + self.source_port + ". Session initiated at: " + self.start_timestamp
        else:
            self.start_notes += "Successful SSH login for: " + self.user_name + " from " + self.ip_address + ":" + self.source_port + ". Session terminated at: " + self.end_timestamp
            self.term_notes += "Successful SSH login for: " + self.user_name + " from " + self.ip_address + ":" + self.source_port + ". Session initiated at: " + self.start_timestamp

    def process_fails(self, m_list, pre_list, fn, raw):
        if m_list[0:2] == ["Invalid", "user"]:
            if self.start_raw_event == "":
                self.start_raw_event = raw
            else:
                self.start_raw_event = self.start_raw_event + " | " + raw
            self.start_timestamp = self.process_timestamp(pre_list[0:3], fn)
            self.isFailedLogin = True
            self.user_name = m_list[2]
            self.ip_address = m_list[4]
            self.source_port = m_list[6]
            self.hostname = pre_list[3]
        elif m_list[0:2] == ["Failed", "password"]:
            if self.term_raw_event == "":
                self.term_raw_event = raw
            else:
                self.term_raw_event = self.term_raw_event + " | " + raw
            self.end_timestamp = self.process_timestamp(pre_list[0:3], fn)
            self.isFailedLogin = True
            self.isSessTerm = True
            self.user_name = m_list[3]
            self.ip_address = m_list[5]
            self.source_port = m_list[7]
            self.hostname = pre_list[3]

    def process_successes(self, m_list, pre_list, fn, raw):
        self.start_timestamp = self.process_timestamp(pre_list[0:3], fn)
        if self.start_raw_event == "":
            self.start_raw_event = raw
        else:
            self.start_raw_event = self.start_raw_event + " | " + raw
        if m_list[0:2] == ["Accepted", "password"]:
            self.isFailedLogin = False
            self.user_name = m_list[3]
            self.ip_address = m_list[5]
            self.source_port = m_list[7]
            self.hostname = pre_list[3]

    def process_terminations(self, m_list, pre_list, fn, raw):
        self.isSessTerm = True
        self.end_timestamp = self.process_timestamp(pre_list[0:3], fn)
        self.hostname = pre_list[3]
        if self.term_raw_event == "":
            self.term_raw_event = raw
        else:
            self.term_raw_event = self.term_raw_event + " | " + raw
        if m_list[0:2] == ["Disconnected", "from"]:
            self.ip_address = m_list[2]
            self.source_port = m_list[4]
        elif m_list[0:2] == ["Received", "disconnect"]:
            self.ip_address = m_list[3]
            self.source_port = m_list[5]
        elif m_list[0:2] == ["Connection", "closed"]:
            self.ip_address = m_list[3]
            self.source_port = m_list[5]

    def process_pam(self, m_list, pre_list, fn, raw):
        self.hostname = pre_list[3]
        if m_list[0][0:8] == "pam_unix":
            pam_type = m_list[0][m_list[0].find("(")+1:m_list[0].find(")")]
            if pam_type.split(":")[1] == "auth":
                if m_list[1:3] == ["check", "pass;"]:
                    self.start_timestamp = self.process_timestamp(pre_list[0:3], fn)
                    if self.start_raw_event == "":
                        self.start_raw_event = raw
                    else:
                        self.start_raw_event = self.start_raw_event + " | " + raw
                    self.isFailedLogin = True
                elif m_list[1:3] == ["authentication", "failure;"]:
                    self.start_timestamp = self.process_timestamp(pre_list[0:3], fn)
                    if self.start_raw_event == "":
                        self.start_raw_event = raw
                    else:
                        self.start_raw_event = self.start_raw_event + " | " + raw
                    self.isFailedLogin = True
                    self.user = m_list[7].split("=")[1]
                    self.ip_address = m_list[8].split("=")[1]
            elif pam_type.split(":")[1] == "session":
                if m_list[1:3] == ["session", "closed"]:
                    self.end_timestamp = self.process_timestamp(pre_list[0:3], fn)
                    if self.term_raw_event == "":
                        self.term_raw_event = raw
                    else:
                        self.term_raw_event = self.term_raw_event + " | " + raw
                    self.user_name = m_list[5]
                    self.isSessTerm = True
                    self.isFailedLogin = False
                elif m_list[1:3] == ["session", "opened"]:
                    if self.start_raw_event == "":
                        self.start_raw_event = raw
                    else:
                        self.start_raw_event = self.start_raw_event + " | " + raw
                    self.start_timestamp = self.process_timestamp(pre_list[0:3], fn)
                    self.user_name = m_list[5]
                    self.isFailedLogin = False
        elif m_list[0][0:14] == "pam_succeed_if":
            if self.start_raw_event == "":
                self.start_raw_event = raw
            else:
                self.start_raw_event = self.start_raw_event + " | " + raw
            self.start_timestamp = self.process_timestamp(pre_list[0:3], fn)
            self.user_name = m_list[9][1:-1]
        elif m_list[0][0:4] == "PAM":
            if self.term_raw_event == "":
                self.term_raw_event = raw
            else:
                self.term_raw_event = self.term_raw_event + " | " + raw
            self.end_timestamp = self.process_timestamp(pre_list[0:3], fn)
            self.user_name = m_list[9].split("=")[1]
            self.ip_address = m_list[10].split("=")[1]

    def processSecureEvent(self, ll, l, p, fn):
        raw_event = l.rstrip()
        msglst = ll[5::]
        message = " ".join(map(str, msglst)).rstrip()
        if self.issupportedEvent(msglst):
            if msglst[0] in self.fails:
                self.process_fails(msglst, ll[0:5], fn, raw_event)
                return True
            elif msglst[0] in self.successes:
                self.process_successes(msglst, ll[0:5], fn, raw_event)
                return True
            elif msglst[0] in self.terminations:
                self.process_terminations(msglst, ll[0:5], fn, raw_event)
                return True
            else:
                self.process_pam(msglst, ll[0:5], fn, raw_event)
                return True
        else:
            print("Unsupported message parser for the message: " + message)
            return False

def print2timeline(all_events, f):
    today = datetime.date.today()
    header = "Date Added, Timestamp (UTC), Timestamp Description, Hostname, Agent ID, Attribution, Event Description, Notes, Owner / Associated User, Associated MD5, Associated SHA1, Size, Source IP, Source Domain, Destination IP, Destination Domain, Data Theft, MD5 HBI\n"
    f.write(header)
    for i in all_events:
        skip_start, skip_term = False, False
        if not all_events[i].start_timestamp:
            all_events[i].start_timestamp = "?? session initiation not found in the log file ??"
            skip_start = True
        if not all_events[i].end_timestamp:
            all_events[i].end_timestamp = "?? session termination not found in the log file ??"
            skip_term = True
        all_events[i].process_notes()
        if not skip_start:
            f.write(str(today) + "," + str(all_events[i].start_timestamp) + "," + "SecureLog Event Timestamp" + "," + all_events[i].hostname + "," + "," + "," + all_events[i].start_raw_event + "," + all_events[i].start_notes + "," + all_events[i].user_name + "," + "," + "," + "," + all_events[i].ip_address + "," + "," + "," + "," + "," + "\n")
        if not skip_term:
            f.write(str(today) + "," + str(all_events[i].end_timestamp) + "," + "SecureLog Event Timestamp" + "," + all_events[i].hostname + "," + "," + "," + all_events[i].term_raw_event + "," + all_events[i].term_notes + "," + all_events[i].user_name + "," + "," + "," + "," + all_events[i].ip_address + "," + "," + "," + "," + "," + "\n")

def main(f, o):
    login_ctr = 0
    d = {}
    secureLog = open(f, "r")
    lines = secureLog.readlines()
    for l in lines:
        llist = l.split()
        p_name = llist[4].split("[")[0]
        if p_name == "sshd":
            pid = llist[4][llist[4].find("[")+1:-2]
            s = SecureLog()
            if s.processSecureEvent(llist, l, pid, f):
                if pid not in d:
                    login_ctr += 1
                    d[pid] = s
                else:
                    d[pid] = d[pid].merge(s)
            else:
                continue


    secureLog.close()
    print("Found " + str(login_ctr) + " SSH login sessions in the Secure Log")

    if login_ctr > 0:
        c = open(o, "w")
        print("Exporting secure log events to a timeline: " + o)
        print2timeline(d, c)
        c.close()
    else:
        print("Didn't find any SSH login events, no timeline needed")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script parses a Linux secure log for login events and exports to CSV')
    parser.add_argument('-f', '--inputFile', nargs='+', required=True, help="secure log file path input")
    parser.add_argument('-o', '--csv', nargs="+", required=True, help="The destination path for the CSV output file")
    args = parser.parse_args()
    main(args.inputFile.pop(), args.csv.pop())
