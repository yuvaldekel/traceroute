from scapy.all import IP, ICMP, Raw, sr1, Net
import datetime
from sys import argv

def main():
    #dst_ip = input("Enter destination: ")
    dst_ip = argv[1]

    alphabet = alphabet_list(end= 'z')

    n = 0
    while True:

        answer, timimg = send_ttl(dst_ip, n, alphabet)
        
        if answer == None:
            #print(f" {n} did not answer after {timimg.total_seconds():.3f} seconds.")
            print(f"{n}  *")
        else:
            n_ip = answer[IP].src
            #print(f"Router {n} ip is {n_ip} took {timimg.total_seconds():.3f} seconds to get an answer.")
            print(f"{n}  {n_ip}  {timimg.total_seconds() * 100 :.3f} ms")

        if answer != None and answer[IP].src == Net(dst_ip):
            break
        
        n +=1

def alphabet_list(start = "A", end = 'z'):
    alphabet = []
    A_ascii = ord(start)
    Z_ascii = ord(end)

    for ascii_rep in range(A_ascii, Z_ascii + 1):
        letter = ascii_rep.to_bytes().decode('ascii')
        if letter.isalpha():
            alphabet.append(letter)
    
    return ''.join(alphabet)


def send_ttl(dst_ip, num, data):
    trace_packet = IP(dst = dst_ip, ttl = num)/ICMP(type = 8, code = 0, id = num, seq = num)/Raw(data)
    start = datetime.datetime.now()
    answer = sr1(trace_packet, timeout =1)
    end = datetime.datetime.now()
    timing =  end - start
    return answer, timing

if __name__ == "__main__":
    main()