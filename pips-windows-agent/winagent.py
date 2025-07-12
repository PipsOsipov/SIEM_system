import win32evtlog
import time

LOG_NAME = "Security"
EVENT_CREATE = 4688
EVENT_END = 4689

def get_last_record_number():
    handle = win32evtlog.OpenEventLog(None, LOG_NAME)
    oldest = win32evtlog.GetOldestEventLogRecord(handle)
    total = win32evtlog.GetNumberOfEventLogRecords(handle)
    return oldest + total - 1

def read_new_events(log_name, last_record):
    handle = win32evtlog.OpenEventLog(None, log_name)
    flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_FORWARDS_READ
    events = []

    while True:
        try:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
        except Exception as e:
            print(f"[!] Read error: {e}")
            break
        if not records:
            break

        for ev in records:
            if ev.RecordNumber <= last_record:
                continue
            if ev.EventID in [EVENT_CREATE, EVENT_END]:
                events.append({
                    "record": ev.RecordNumber,
                    "event_id": ev.EventID,
                    "time": ev.TimeGenerated.Format(),
                    "strings": ev.StringInserts
                })

    return events

def main():
    last_record = get_last_record_number()
    print("[*] Process Monitoring...")
    while True:
        events = read_new_events(LOG_NAME, last_record)
        if events:
            for e in events:
                if e["event_id"] == EVENT_CREATE:
                    try:
                        proc_name = e["strings"][5]
                    except Exception:
                        proc_name = "Unknown"
                    print(f"[{e['time']}] Start process: {proc_name}")
                elif e["event_id"] == EVENT_END:

                    print(f"[{e['time']}] Terminate process: Unknown")
                print("-" * 40)
            last_record = max(e["record"] for e in events)

        time.sleep(0.3)

if __name__ == "__main__":
    main()
