from scapy.all import IP, ICMP, Raw, sr1

def alphabet_list(start = "A", end = 'z'):
    alphabet = []
    A_ascii = ord(start)
    Z_ascii = ord(end)

    for ascii_rep in range(A_ascii, Z_ascii + 1):
        letter = ascii_rep.to_bytes().decode('ascii')
        if letter.isalpha():
            alphabet.append(letter)
    
    return ''.join(alphabet)


def send_ttl(num, data):
    trace_packet = IP(dst = "www.google.com", ttl = num)/ICMP(type = 8, code = 0, id = num, seq = num)/Raw(data)
    answer = sr1(trace_packet, timeout =1)
    return answer

def main():
    alphabet = alphabet_list(end= 'z')

    for n in range(1,4):
        answer = send_ttl(n, alphabet)
        
        if answer == None:
            print(f"router {n} did not answer")
        else:
            n_ip = answer[IP].src
            print(f"The {n} router ip is {n_ip}.")

if __name__ == "__main__":
    main()