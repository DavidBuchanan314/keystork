import keystork

device = keystork.Device()

with device.connect() as conn:
    conn.system("uname -a")
    print(conn.check_output(["/system/bin/id"]))
    print(conn.read_file("/proc/version"))
