# Linux Audit Parse
# Developed by Greg Wood
# version 0.0.1 (2021-08-29)
# version 0.0.2 (2021-08-30)

import argparse
import datetime

class AuditEvent:
    syscall_processed = False
    proctitle_processed = False
    raw_event = ""
    timestamp = ""
    event_id = 0
    success = ""
    exit_code = ""
    parent_pid = ""
    process_id = ""
    user_id = ""
    effective_uid = ""
    tty = ""
    session = ""
    cmd = ""
    path = ""
    proctitle = ""

    def merge(self, adding):
        if self.syscall_processed and not self.proctitle_processed and adding.proctitle_processed and not adding.syscall_processed:
            # we're merging the existing syscall record with the new proctitle record
            self.raw_event += adding.raw_event
            self.proctitle = adding.proctitle
            self.proctitle_processed = True
        elif self.proctitle_processed and not self.syscall_processed and not adding.proctitle_processed and adding.syscall_processed:
            # we're merging the existing proctitle record with the new syscall record
            self.raw_event += adding.raw_event
            self.success = adding.success
            self.exit_code = adding.exit_code
            self.parent_pid = adding.parent_pid
            self.process_id = adding.process_id
            self.user_id = adding.user_id
            self.effective_uid = adding.effective_uid
            self.tty = adding.tty
            self.session = adding.session
            self.cmd = adding.cmd
            self.path = adding.path
            self.syscall_processed = True

        return self

    def process_timestamp(self, ts):
        te = ts[ts.find("(")+1:ts.find(")")].split(":")
        epoch = te[0].split(".")
        return datetime.datetime.utcfromtimestamp(int(epoch[0])), int(te[1])

    def process_syscall(self, ll, l):
        self.raw_event += l.rstrip()
        self.timestamp, self.event_id = self.process_timestamp(ll[1])
        self.success = ll[4].split("=")[1]
        self.exit_code = ll[5].split("=")[1]
        self.parent_pid = ll[11].split("=")[1]
        self.process_id = ll[12].split("=")[1]
        self.user_id = ll[14].split("=")[1]
        if self.user_id == "0":
            self.user_id = "root"
        self.effective_uid = ll[16].split("=")[1]
        if self.effective_uid == "0":
            self.effective_uid = "root"
        self.tty = ll[22].split("=")[1]
        self.session = ll[23].split("=")[1]
        self.cmd = ll[24].split("=")[1][1:-1]
        self.path = ll[25].split("=")[1][1:-1]
        self.syscall_processed = True

    def process_proctitle(self, ll, l):
        self.raw_event += l.rstrip()
        self.timestamp, self.event_id = self.process_timestamp(ll[1])
        # converting \x00 null bytes to spaces to match command line syntax entered
        self.proctitle = self.hex_convert(ll[2])
        self.proctitle_processed = True

    def hex_convert(self, ll):
        orig = ll.split("=")[1]
        hex_list = [orig[i:i+2] for i in range(0, len(orig), 2)]
        res = ""
        # replace \\00 (null) bytes with spaces \x20
        for i in range(len(hex_list)):
            if hex_list[i] == "00":
                hex_list[i] = "20"
            if hex_list[i][0] not in "0123456789ABCDEFabcdef":
                return orig
            elif hex_list[i][1] not in "0123456789ABCDEFabcdef":
                return orig
            res += bytearray.fromhex(hex_list[i]).decode()
        return res

def print2timeline(all_events, f):
    today = datetime.date.today()
    header = "Date Added, Timestamp (UTC), Timestamp Description, Hostname, Agent ID, Attribution, Event Description, Notes, Owner / Associated User, Associated MD5, Associated SHA1, Size, Source IP, Source Domain, Destination IP, Destination Domain, Data Theft, MD5 HBI\n"
    f.write(header)
    for i in all_events:
        f.write(str(today) + "," + str(all_events[i].timestamp) + "," + "AuditLog Event Timestamp" + "," +  "," + "," + "," + all_events[i].raw_event + "," + all_events[i].proctitle + "," + all_events[i].user_id + "," + "," + "," + "," + "," + "," + "," + "," + "," + "\n")

def main(f, o):
    sc, pc = 0, 0
    d = {}
    auditLog = open(f, "r")
    lines = auditLog.readlines()
    for l in lines:
        llist = l.split()
        if llist[0] == "type=SYSCALL":
            sc += 1
            s = AuditEvent()
            s.process_syscall(llist, l)
            if s.event_id not in d:
                d[s.event_id] = s
            else:
                d[s.event_id] = d[s.event_id].merge(s)
        elif llist[0] == "type=PROCTITLE":
            pc += 1
            p = AuditEvent()
            p.process_proctitle(llist, l)
            if p.event_id not in d:
                d[p.event_id] = p
            else:
                d[p.event_id] = d[p.event_id].merge(p)

    auditLog.close()
    print("Found " + str(sc) + " SYSCALL events and " + str(pc) + " PROCTITLE events in the Audit Log")

    if sc > 0 or pc > 0:
        c = open(o, "w")
        print("Exporting audit events to a timeline: " + o)
        print2timeline(d, c)
        c.close()
    else:
        print("Didn't find any SYSCALL or PROCTITLE events, no timeline needed")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script parses a Linux audit log for command execution and exports to CSV')
    parser.add_argument('-f', '--inputFile', nargs='+', required=True, help="audit log file path input")
    parser.add_argument('-o', '--csv', nargs="+", required=True, help="The destination path for the CSV output file")
    args = parser.parse_args()
    main(args.inputFile.pop(), args.csv.pop())




