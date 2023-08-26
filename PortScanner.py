from datetime import datetime
import nmap
import ipaddress
import concurrent.futures

def target_list(ip_target):
    ip_list = ''
    for addr in ipaddress.IPv4Network(ip_target):
        ip_list = ip_list + ' ' + str(addr)
    ip_list = ip_list.split()
    del ip_list[-1]
    del ip_list[0]
    print(ip_list[0],'~',ip_list[-1])
    return ip_list


def scan_host(i):
    scan_range = scanner.scan(hosts=i, arguments='-n -sP -PE -PA21,23,80,3389')
    scan_range = scan_range['scan'][i]
    scan_range = str(scan_range)
    if scan_range.find("up") != -1:
        host_list.append(i)
    else:
        pass


def logsort(answer):
    return answer['Id']


def logging(logs):
    global now
    logs.sort(key=logsort)
    write_log = str(logs)
    write_log = write_log.replace('}', '\n')
    write_log = write_log.replace('{', '\n')
    log = open('Log ' + str(now) + '.txt', 'w')
    log.write(write_log)
    log.close()


def portscanner(name,ip_target,ini, end):
    global log_data
    ports_opened = ""
    ports_closed = ""
    for i in range(ini, end + 1):
        res = scanner.scan(ip_target, str(i))
        res = str(res)
        if res.find('open') != -1:
            ports_opened = ports_opened + " " + str(i)
        else:
            ports_closed = ports_closed + " " + str(i)
    log_data.append({"Id": name, "Ports Closed": ports_closed, "Ports Opened": ports_opened, "Ip": ip_target})


def fiware(ip_target, name):
    global log_data
    scan_list = ('27017', '1026', '8666', '1883', '4041')
    count = 0
    for i in scan_list:
        res = scanner.scan(ip_target, i)
        res = str(res)
        if res.find('open') != -1:
            count += 1
        else:
            break
    if count == 5:
        log_data.append({'Id': name, 'Status': 'Fiware Dectected', 'Ip': ip_target})
    else:
        log_data.append({'Id': name, 'Status': 'Fiware Not Dectected', 'Ip': ip_target})


def phpadmin(name,ip_target=''):
    global log_data
    status_list = ([''] * 3)
    scan_list = ('3306', '80', '8080', '443')
    count = 0
    for i in scan_list:
        res = scanner.scan(ip_target, i)
        res = str(res)
        if res.find("open") != -1:
            count += 1
        else:
            break
    if count == 4:
        log_data.append({"Id": name, "Status": "PhpAdmin Detected", "Ip": ip_target})

    else:
        log_data.append({"Id": name, "Status": "PhpAdmin Not Detected", "Ip": ip_target})


def main_menu():
    global target, now, host_list
    count = 0
    host_list = []
    while True:
        option = -1
        if option <= 0 or option >= 4:
            target = input("Insira um ip alvo: ")
            print("Criando lista de alvos")
            with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
                for i in target_list(target):
                    executor.submit(scan_host, i)
            print("1.PortScan\n2.Fiware detector\n3.PhpAdmin Detector\n4.Exit")
            option = int(input("Insira uma opção: "))
        if option == 1:
            inicial_port = int(input("Insira a porta inicial: "))
            end = int(input("Insira a porta final: "))
            now = str(datetime.now())
            now = now.replace(":", "_")
            with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
                for addr in host_list:
                    count += 1
                    executor.submit(portscanner, count, str(addr), inicial_port, end)

        elif option == 2:
            now = str(datetime.now())
            now = now.replace(":", "_")
            with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
                for addr in host_list:
                    count += 1
                    executor.submit(fiware, str(addr), count)
                print("Escaneando Alvos, Espere!!!")

        elif option == 3:
            now = str(datetime.now())
            now = now.replace(":", "_")
            with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
                for addr in host_list:
                    count += 1
                    executor.submit(phpadmin, count,str(addr))
                print("Escaneando Alvos, Espere!!!")
        else:
            break
        logging(log_data)

host_list = []
now = ""
scanner = nmap.PortScanner()
log_data = []
target = ""
end = 0
inicial_port = 0
main_menu()
print(log_data)
