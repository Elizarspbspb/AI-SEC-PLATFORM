def read_log(filename):
    with open(filename, "r") as f:
        logs = f.readlines()
    return logs

def filter_security_events(logs):
    suspicious=[]
    keywords=[
        "failed password",
        "sudo",
        "permission denied",
        "root",
        "exploit"
    ]
    for line in logs:
        for word in keywords:
            if word in line.lower():
                suspicious.append(line)
    return suspicious

if __name__=="__main__":
    logs=read_log(
        "../raw_logs/syslog.txt"
    )
    result=filter_security_events(logs)
    for event in result:
        print(event)
