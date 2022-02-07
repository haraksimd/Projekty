'''
created by: Daniel Haraksim
project: UDP_communicator
description: A simple communicator between server and a client. Client is able to send files or messages to server.
Assignment was meant to be coded in one python file.
'''

import socket
import os
import math
import time
import zlib
from tkinter import Tk
from tkinter.filedialog import askopenfilename

#Header
SPRAVA = 0
SYN = 1
ACK = 2
FIN = 4
NACK = 8
SUBOR = 32
ZMENA = 64

def poslat_subor(chyba, fragment,addr, klient):
    chybny_fragment = 0
    fragment_counter = 1
    klient.send(SUBOR.to_bytes(1, "big"))

    root = Tk()
    root.withdraw()

    filename = askopenfilename() #windows popup okno na vybranie suboru
    filesize = os.path.getsize(filename) #zistenie velkosti subora

    fragment_max = int(math.ceil(filesize/fragment)) #vypocet kolko fragmentov posiela
    if fragment_max < 1:
        fragment_max = 1
    if chyba == 1:
        print(f"Na akom fragmente chceš simulovať chybu ? Vyber si z intervalo od 1 po {fragment_max}")
        chybny_fragment = input()
        chybny_fragment = int(chybny_fragment)

    klient.send(f"{filename}".encode()) #posle serveru nazov suboru

    print(f"Posielam súbor {os.path.abspath(filename)} s veľkosťou {filesize}B")
    with open(filename, "rb") as f:
        signal = SYN.to_bytes(1, "big")
        while True:
            flag = klient.recv(1500)            #ocakava signalizacnu spravu, bud ACK aby mohol program poslat alebo NACK aby zistil ci bol subor corruptnuty
            if flag == ACK.to_bytes(1,"big"):   #ak pride ACK
                if signal == FIN.to_bytes(1, "big"):
                    klient.sendto(signal, addr)
                    break
                bytes_read = f.read(fragment)   #cita byte zo suboru vo velkosti urceneho fragmentu pouzivatelom
                checksum_klient = (zlib.crc32(bytes_read)).to_bytes(4, "big")   #Vypocita sa checksum
                data = signal + checksum_klient + bytes_read #header + data
                # ak chce pouzivatel simulovat chybu, tak najde na akom fragmente ma simulovat chybu
                if chyba == 1 and chybny_fragment == fragment_counter:
                    bytes_read = bytes_read[1:] + b'1'
                    data_c = signal + checksum_klient + bytes_read
                    klient.sendall(data_c)  #posle packet s 1 bytom corruptnutym
                else:
                    klient.sendall(data) # inak posielame normalne bez chyby
                print(f"{fragment_counter}/{fragment_max} poslaných fragmenttov")
                if fragment_counter == fragment_max:
                    signal = FIN.to_bytes(1, "big")
                fragment_counter += 1
            elif flag == NACK.to_bytes(1,"big"): #ak pride NACK tak znamena, ze fragment subore bol poslany zle
                print(f"{fragment_counter-1}. fragment bol corruptnutý")
                print(f"Posielam {fragment_counter-1}. fragment znova")
                klient.sendall(data)


# posielani spravy funguje ako posielanie suboru len pracuje s inputom od pouzivatela
def poslat_spravu(chyba, fragment, addr, klient):
    global checksum_klient, bytes_read, data
    pozicia = 0
    chybny_fragment = 0
    fragment_counter = 1
    klient.send(SPRAVA.to_bytes(1,"big"))

    print("Napíš správu, ktorú chceš poslať:")
    sprava = input().encode()
    dlzka = len(sprava)

    fragment_max = int(math.ceil(dlzka/fragment))
    if fragment_max < 1:
        fragment_max = 1

    if chyba == 1:
        print(f"Na akom fragmente chceš simulovať chybu ? Vyber si z intervalo od 1 po {fragment_max}")
        chybny_fragment = input()
        chybny_fragment = int(chybny_fragment)

    signal = SYN.to_bytes(1,"big")
    while True:
        flag = klient.recv(1500)
        if flag == ACK.to_bytes(1,"big"):
            if signal == FIN.to_bytes(1,"big"):
                klient.sendto(signal,addr)
                break
            bytes_read = sprava[pozicia:fragment+pozicia]
            checksum_klient = (zlib.crc32(bytes_read)).to_bytes(4, "big")
            data = signal + checksum_klient + bytes_read


            if chyba == 1 and chybny_fragment == fragment_counter:
                bytes_read = bytes_read[1:] + b'1'
                data_c = signal + checksum_klient + bytes_read
                klient.sendall(data_c)
            else:
                data = signal + checksum_klient + bytes_read
                klient.sendto(data,addr)
            print(f"{fragment_counter}/{fragment_max} poslaných fragmentov")
            if fragment_counter == fragment_max:
                signal = FIN.to_bytes(1,"big")
            fragment_counter += 1
            pozicia = pozicia+fragment

        elif flag == NACK.to_bytes(1, "big"):
            print(f"{fragment_counter - 1}. fragment bol corruptnutý")
            print(f"Posielam {fragment_counter - 1}. fragment znova")
            klient.sendall(data)

# ak si pouzivatel zvoli na zaciatku programu, ze chce byt serverom zavola a tato funkcia
def server():
    # zistovanie IP servera
    localIP = socket.gethostbyname(socket.gethostname())
    # urcovanie portu
    print("Zadaj port na ktorom chces pocuvat")
    localPort = input()
    localPort = int(localPort)
    ADDRESS = (localIP, localPort)

    # incializovanie servera
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((localIP, localPort))
    print(f"Server beží a počúva na adrese {ADDRESS}")

    while True: #server bezi pokial ho nevypneme
        data, addr = server.recvfrom(1500)                  #server pocuva pokial sa niekto nepripoji na jeho socket
        if data == SYN.to_bytes(1, "big"):                  #caka kym pride signalizacna sprava SYN
            server.sendto(ACK.to_bytes(1, "big"), addr)     #ak pride, posle naspat ACK a dokonci two-way handshake
            print(f"Pripojenie zabezpečené s {addr}")

        while True:
            hlavicka = server.recv(1500)                        #ocakava signalizacnu spravu ci klient posiela subor alebo spravu
            full_msg = ""
            if hlavicka == SUBOR.to_bytes(1, "big"):            #ak prida v hlavicke signalizacna sprava SUBOR
                server.sendto(ACK.to_bytes(1, "big"), addr)     #posle klientovi ACK signal aby indikoval klientovi, ze moze posielat
                fragment_counter = 1

                received = server.recv(1500).decode()           #prijme nazov suboru
                filename = received
                filename = os.path.basename(filename)           #zbavi sa absolutnej cesty ak nejaka je
                print(f"Príjmaš súbor {filename}, napíš cestu kde chceš tento súbor uložiť")
                filename = input()

                with open(filename, "wb") as f:
                    while True:
                        packet = server.recv(1500)
                        header = packet[0]
                        checksum_klient = packet[1:5]
                        bytes_read = packet[5:]
                        if header == FIN:    #ak pride signalizacna sprava FIN zisti, ze je koniec
                            f.close()
                            print("Súbor uložený v", os.path.abspath(filename))
                            break
                        checksum_server = (zlib.crc32(bytes_read)).to_bytes(4, "big")         #ak neprijde zatial FIN porovnava checksum
                        if checksum_server == checksum_klient:                                #ak sa rovnaju tak ich zapisem do noveho subora ktory uklada
                            f.write(bytes_read)
                            server.sendto(ACK.to_bytes(1, "big"), addr)                       #po prijati fragmentu odosle naspat ACK signal
                            size = len(bytes_read)                                            #vypocet velkosti fragmentu
                            print(f"Fragment {fragment_counter} prijatý s veľkosťou: {size}B")

                            fragment_counter += 1
                        else:
                            server.sendto(NACK.to_bytes(1, "big"), addr)                      #ak sa checksum nerovna posle NACK
                            print(f"Fragment {fragment_counter} neprijatý kvôli CRC error")
                            continue
            #pri prijmani spravy to funguje skoro rovnako ako subor ale neprepisujeme do suboru ale spravu len vypisujeme
            elif hlavicka == SPRAVA.to_bytes(1, "big"):
                fragment_counter = 1
                server.sendto(ACK.to_bytes(1, "big"), addr)
                while True:
                    packet = server.recv(1500)
                    header = packet[0]
                    checksum_klient = packet[1:5]
                    bytes_read = packet[5:]

                    if header == FIN:
                        break
                    checksum_server = (zlib.crc32(bytes_read)).to_bytes(4, "big")
                    if checksum_server == checksum_klient:
                        msg = bytes_read.decode()
                        full_msg = full_msg + msg
                        server.sendto(ACK.to_bytes(1, "big"), addr)
                        size = len(bytes_read)
                        print(f"Fragment {fragment_counter} prijatý s veľkosťou: {size}B")

                        fragment_counter += 1
                    else:
                        server.sendto(NACK.to_bytes(1, "big"), addr)
                        print(f"Fragment {fragment_counter} neprijatý kvôli CRC error")
                        continue

                print(full_msg)
            elif hlavicka == FIN.to_bytes(1, "big"):                #ak pride hlavicka s FIN flagom
                server.sendto(ACK.to_bytes(1, "big"), addr)         #odoslem ACK na dokoncenie two way handshaku
                print(f"Pripojenie uzavreté s {addr} ")
                break
            elif hlavicka == ZMENA.to_bytes(1, "big"):              #ak pride hlavicka so ZMENA flagom
                print("Klient chce vymeniť zariadenia")
                server.sendto(ACK.to_bytes(1, "big"), addr)         #odoslem ack, vypnem server a zapnem klienta
                server.close()
                time.sleep(0.5)
                klient()


def klient():
    #urcenie IP a portu prijmaca na ktory sa chceme pripojit
    print("Zadaj IP adresu na, ktoru sa chces pripojit")
    SERVER = input()
    print("Zadaj IP adresu na, ktoru sa chces pripojit")
    PORT = input()
    PORT = int(PORT)
    ADRESA = ((SERVER, PORT))

    #inicializacia klienta
    klient = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    klient.sendto(SYN.to_bytes(1, "big"), ADRESA)

    #ocakavam ACK signalizacnu spravu
    data, addr = klient.recvfrom(1500)
    if data == ACK.to_bytes(1, "big"):
        klient.connect(addr)
        print(f"Pripojený na server: {addr}")

    print("Zadaj max. veľkosť fragmentu (max = 1467) :")        #zadanie maximalnej velkosti fragmentu, max 1456 lebo
    fragment = input()                                          #1518 eth(18) - IP header(20) - UDP header(8) = 1472
    fragment = int(fragment)                                    #1472 - moj protokol(5) = 1467

    while True:
        print("Akú akciu chceš vykonať 0-poslať správu, 1 - poslať súbor, 2 - ukončiť spojenie, 3 - zahajit zmenu zariadeni")
        akcia = input()
        if akcia == "1":
            print("Chces simulovat chybu ?, 0-nie, 1-ano")
            chyba = input()
            if chyba == "0":
                poslat_subor(0, fragment, addr, klient)
            elif chyba == "1":
                poslat_subor(1, fragment, addr, klient)
        elif akcia == "0":
            print("Chces simulovat chybu ?, 0-nie, 1-ano")
            chyba = input()
            if chyba == "0":
                poslat_spravu(0, fragment, addr, klient)
            elif chyba == "1":
                poslat_spravu(1, fragment, addr, klient)
        elif akcia == "2":
            klient.sendto(FIN.to_bytes(1, "big"), addr)         #na ukoncenie pripojenie posleme FIN flag
            flag = klient.recv(1500)
            if flag == ACK.to_bytes(1,"big"):                   #ocakavame naspat ACK na dokoncenie two way handshaku
                klient.close()                                  #uzavriem socket
                print("Pripojenie zrušené")
                break
        elif akcia == "3":
            klient.sendto(ZMENA.to_bytes(1, "big"), addr)       #inicializujem zmenu pomocou ZMENA flagu
            if klient.recv(1500) == ACK.to_bytes(1,"big"):      #pride mi ACK flag, zavriem klient socket a zavolam funkciu servera
                klient.close()
                server()


print("Vyber si aké zariadnie chceš byť 1-server, 2 klient")
zariadenie = input()
if zariadenie == "1":
    server()
elif zariadenie == "2":
    klient()
