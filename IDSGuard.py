from scapy.all import sniff, IP, TCP
import smtplib
from termcolor import cprint
import sys

cprint('''


 _____ _____    _     ______                      _   
(_____|____ \  | |   / _____) Made by hei$enberg | |  
   _   _   \ \  \ \ | /  ___ _   _  ____  ____ _ | |  
  | | | |   | |  \ \| | (___) | | |/ _  |/ ___) || |  
 _| |_| |__/ /____) ) \____/| |_| ( ( | | |  ( (_| |  
(_____)_____(______/ \_____/ \____|\_||_|_|   \____|  
                                                                    
                                    
            Welcome to IDSGuard!
                    ***


    ''', 'blue')
cprint(' sniffing... ', 'yellow')
syn_count = 0
failed_login_attempts = {}

sender_email = "secguardrelq@gmail.com"
receiver_email = "radioheadl1515@gmail.com"
password = "nhhlskdthicnoggc"
subject = "IDSGuard: Security Alert!"

def send_email(body):
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, password)
        email_message = f'Subject: {subject}\n\n{body}'
        server.sendmail(sender_email, receiver_email, email_message)

def detect_scan(pkt):
    global syn_count
    global failed_login_attempts
    global event_detected
    

    if pkt.haslayer(TCP) and pkt[TCP].flags == 2:
        syn_count += 1
        if syn_count > 10:
            src_ip = pkt[IP].src
            print(' ')
            cprint('Scanning detected', 'red')
            body = f'Scanning detected. High probability that your machine is being scanned right now from {src_ip}'
            send_email(body)
            sys.exit()
            
    elif pkt.haslayer(TCP) and pkt[TCP].dport==22:
        src_ip = pkt[IP].src
        if src_ip not in failed_login_attempts:
            failed_login_attempts[src_ip] = 0
        failed_login_attempts[src_ip] += 1

        if failed_login_attempts[src_ip] > 3:
            print(' ')
            cprint('Brute force attack', 'red')
            body = f"High probability of brute force attack from {src_ip}"
            send_email(body)
            sys.exit()



if __name__ == '__main__':
    sniff(prn=detect_scan, filter="tcp", store=0)


