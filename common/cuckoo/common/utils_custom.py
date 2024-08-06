import requests

def InstallVNC(ip, port):

    ret = {}

    files = {
        'file': open('/opt/cuckoo3/exec//tightvnc-2.8.84-gpl-setup-64bit.msi', 'rb'),
        'filepath': (None, 'c:\\tightvnc-2.8.84-gpl-setup-64bit.msi'),
    }

    response = requests.post("http://{}:{}/store".format(ip, port), files=files)

    ret['upload_status'] = response.status_code
    ret['upload_message'] = str(response.content.decode('utf-8').strip())

    files = {
        'command': (None, 'powershell.exe -command "msiexec /i c:\\tightvnc-2.8.84-gpl-setup-64bit.msi /quiet /norestart ADDLOCAL=Server SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=1 SET_PASSWORD=1 VALUE_OF_PASSWORD=password"'),
    }

    response = requests.post("http://{}:{}/execute".format(ip, port), files=files)

    ret['exec_status'] = response.status_code
    ret['exec_message'] = str(response.content.decode('utf-8').strip())

    return ret
